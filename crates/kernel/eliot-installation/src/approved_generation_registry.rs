//! Approved-generation activation state and receipt-bound rebind lifecycle.
//!
//! This module owns the installation authority projection described by
//! Architecture `A11.3` and Implementation `I3.4`, `I3.15`: immutable
//! generation admission, pending/active transitions, last-known-good state,
//! and exact Phase-B receipt/fence bindings. The redb backend remains in the
//! parent module; this module only defines the state and transition closure.
//!
//! Phase-B rebind records preserve the explicit owner/epoch and receipt
//! boundaries required by Implementation `I3.15` and Architecture `A12.6`.

use std::collections::BTreeSet;
use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    AGENT_BRIDGE_SOURCE_MAX_BYTES, CandidateManifest, ContractVersion, FileIdentity,
    HostPhaseBMaterializationIntent, HostPhaseBMaterializationReceipt, HostPhaseBPreparedReceipt,
    HostPhaseBStaticTemplate, INSTALLATION_REGISTRY_WIRE_VERSION, InstallationActivationApproval,
    InstallationError, InstallationProfile, InstallationTransaction,
    InstallerServiceRegistrationApproval, InstallerServiceRole, PHASE_B_PENDING_MARKER,
    PHASE_B_PENDING_SCM_DIGEST, PlatformAgentBridgeSecurityConvergenceReceipt,
    PlatformAgentBridgeStagePrepared, PlatformAgentBridgeStagingReceipt, PlatformHandle,
    ProvisionedSupervisionAuthority, ResourceGeneration, RuntimeLaunchDescriptor, StateFence,
    canonical_json_bytes, handle, sha256_handle, sha256_hex, text,
};

#[cfg(test)]
use super::HostOwnerEpochCapability;

/// Wire-level state of a Host-owned Phase-B physical digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseBDigestState {
    /// Phase A has declared the destination but Host has not published it.
    Pending,
    /// Host has an exact physical SHA-256 for the published destination.
    Live,
}

/// Classifies one Phase-B digest without treating the pending marker as a
/// syntactically valid SHA-256.
pub fn phase_b_digest_state(
    value: &PlatformHandle,
    field: &str,
) -> Result<PhaseBDigestState, InstallationError> {
    if value.as_str() == PHASE_B_PENDING_MARKER {
        handle(value, field)?;
        return Ok(PhaseBDigestState::Pending);
    }
    if value.as_str() == PHASE_B_PENDING_SCM_DIGEST {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "the SCM pending selector is adapter-only and cannot be runtime authority"
                .to_owned(),
        });
    }
    if value.as_str() == super::LEGACY_PHASE_B_ZERO_DIGEST {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "reserved Phase-B pending marker cannot be used as a live physical digest"
                .to_owned(),
        });
    }
    sha256_handle(value, field)?;
    Ok(PhaseBDigestState::Live)
}

/// Converts the typed runtime Phase-B state to the hashed selector required by
/// the SCM adapter. The hashed pending selector never crosses back into the
/// runtime authority fields.
pub fn phase_b_scm_selector(value: &PlatformHandle) -> Result<PlatformHandle, InstallationError> {
    match phase_b_digest_state(value, "phase_b.scm_selector")? {
        PhaseBDigestState::Pending => {
            PlatformHandle::new(PHASE_B_PENDING_SCM_DIGEST).map_err(|error| {
                InstallationError::InvalidField {
                    field: "phase_b.scm_selector".to_owned(),
                    reason: error.to_string(),
                }
            })
        }
        PhaseBDigestState::Live => Ok(value.clone()),
    }
}

pub(crate) fn phase_b_scm_digest(
    value: &PlatformHandle,
) -> Result<PlatformHandle, InstallationError> {
    phase_b_scm_selector(value)
}

pub(crate) fn validate_phase_b_scm_digest(
    value: &PlatformHandle,
    field: &str,
) -> Result<(), InstallationError> {
    if value.as_str() == super::LEGACY_PHASE_B_ZERO_DIGEST {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "legacy zero digest cannot be used as an SCM selector".to_owned(),
        });
    }
    if value.as_str() == PHASE_B_PENDING_MARKER {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "runtime pending marker must be mapped to the adapter SCM selector".to_owned(),
        });
    }
    sha256_handle(value, field)
}

/// One artifact generation admitted by installation policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedGeneration {
    /// The complete immutable candidate manifest.
    pub manifest: CandidateManifest,
    /// Full transaction-bound activation approval.
    pub approval: InstallationActivationApproval,
    /// Whether this generation is currently active.
    pub active: bool,
    /// Whether this generation is the last-known-good activation.
    pub last_known_good: bool,
}

/// Durable provider-neutral proof that an auxiliary Agent Bridge stage was
/// prepared but not yet published.  The Windows adapter maps its retained
/// temporary-file identity into this record; the installation registry owns
/// the transaction and recovery authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBridgeStagePrepared {
    /// Explicit durable stage-prepared wire discriminator.
    pub wire: PlatformHandle,
    /// Installation identity bound to the launch contour.
    pub installation_id: PlatformHandle,
    /// Sole installation transaction identity.
    pub transaction_id: PlatformHandle,
    /// Immutable installer plan identity.
    pub installation_plan_digest: PlatformHandle,
    /// Phase-B effect identity.
    pub effect_id: PlatformHandle,
    /// Exact Phase-B request identity.
    pub request_digest: PlatformHandle,
    /// Digest of the retained Host state root.
    pub host_state_root_digest: PlatformHandle,
    /// Candidate manifest identity.
    pub manifest_digest: PlatformHandle,
    /// Runtime launch descriptor identity.
    pub launch_descriptor_digest: PlatformHandle,
    /// Exact launch generation.
    pub launch_generation: PlatformHandle,
    /// Source executable path and retained identity.
    pub source_path: PlatformHandle,
    /// Source executable object identity.
    pub source_identity: FileIdentity,
    /// Source executable SHA-256.
    pub source_sha256: PlatformHandle,
    /// Source executable byte length.
    pub source_size: u64,
    /// Same-parent operation-scoped temporary path.
    pub temporary_path: PlatformHandle,
    /// Temporary object identity captured before durable publication.
    pub temporary_identity: FileIdentity,
    /// Deterministic final destination path.
    pub destination_path: PlatformHandle,
    /// Final destination parent identity.
    pub destination_parent_identity: FileIdentity,
    /// Digest of all fields except this digest.
    pub prepared_digest: PlatformHandle,
}

impl AgentBridgeStagePrepared {
    /// Current durable stage-prepared wire.
    pub const WIRE: &'static str = "eliot.host.agent-bridge-stage-prepared.v1";

    /// Recomputes the domain-separated stage-prepared identity.
    pub fn computed_digest(&self) -> Result<PlatformHandle, InstallationError> {
        let bytes = canonical_json_bytes(&(
            (
                Self::WIRE,
                self.installation_id.as_str(),
                self.transaction_id.as_str(),
                self.installation_plan_digest.as_str(),
                self.effect_id.as_str(),
                self.request_digest.as_str(),
                self.host_state_root_digest.as_str(),
                self.manifest_digest.as_str(),
                self.launch_descriptor_digest.as_str(),
                self.launch_generation.as_str(),
            ),
            (
                self.source_path.as_str(),
                self.source_identity,
                self.source_sha256.as_str(),
                self.source_size,
            ),
            (
                self.temporary_path.as_str(),
                self.temporary_identity,
                self.destination_path.as_str(),
                self.destination_parent_identity,
            ),
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "agent_bridge.stage_prepared.prepared_digest".to_owned(),
            reason: error.to_string(),
        })?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
            field: "agent_bridge.stage_prepared.prepared_digest".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Validates the durable stage proof without adopting any destination.
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.wire.as_str() != Self::WIRE {
            return Err(InstallationError::MigrationRequired {
                reason: "agent-bridge stage-prepared wire requires explicit re-stage".to_owned(),
            });
        }
        for (value, field) in [
            (&self.installation_id, "agent_bridge.installation_id"),
            (&self.transaction_id, "agent_bridge.transaction_id"),
            (
                &self.installation_plan_digest,
                "agent_bridge.installation_plan_digest",
            ),
            (&self.effect_id, "agent_bridge.effect_id"),
            (&self.request_digest, "agent_bridge.request_digest"),
            (
                &self.host_state_root_digest,
                "agent_bridge.host_state_root_digest",
            ),
            (&self.manifest_digest, "agent_bridge.manifest_digest"),
            (
                &self.launch_descriptor_digest,
                "agent_bridge.launch_descriptor_digest",
            ),
            (&self.launch_generation, "agent_bridge.launch_generation"),
            (&self.source_path, "agent_bridge.source_path"),
            (&self.temporary_path, "agent_bridge.temporary_path"),
            (&self.destination_path, "agent_bridge.destination_path"),
        ] {
            handle(value, field)?;
        }
        for (value, field) in [
            (
                &self.installation_plan_digest,
                "agent_bridge.installation_plan_digest",
            ),
            (&self.request_digest, "agent_bridge.request_digest"),
            (
                &self.host_state_root_digest,
                "agent_bridge.host_state_root_digest",
            ),
            (&self.manifest_digest, "agent_bridge.manifest_digest"),
            (
                &self.launch_descriptor_digest,
                "agent_bridge.launch_descriptor_digest",
            ),
            (&self.source_sha256, "agent_bridge.source_sha256"),
            (&self.prepared_digest, "agent_bridge.prepared_digest"),
        ] {
            sha256_handle(value, field)?;
        }
        if self.source_size == 0 || self.source_size > AGENT_BRIDGE_SOURCE_MAX_BYTES {
            return Err(InstallationError::InvalidField {
                field: "agent_bridge.source_size".to_owned(),
                reason: "must be non-zero and within the source bound".to_owned(),
            });
        }
        if self.source_identity.volume_serial_number == 0
            || self.source_identity.file_index == 0
            || self.temporary_identity.volume_serial_number == 0
            || self.temporary_identity.file_index == 0
            || self.destination_parent_identity.volume_serial_number == 0
            || self.destination_parent_identity.file_index == 0
        {
            return Err(InstallationError::InvalidField {
                field: "agent_bridge.stage_prepared.file_identity".to_owned(),
                reason: "must identify non-zero file objects".to_owned(),
            });
        }
        if self.prepared_digest != self.computed_digest()? {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    /// Adapts the Windows provider capability into this durable installation
    /// shape. The caller supplies context owned by the pending Phase-B intent.
    #[allow(clippy::too_many_arguments)]
    pub fn from_platform(
        prepared: &PlatformAgentBridgeStagePrepared,
        installation_id: PlatformHandle,
        installation_plan_digest: PlatformHandle,
        host_state_root_digest: PlatformHandle,
        manifest_digest: PlatformHandle,
        launch_descriptor_digest: PlatformHandle,
        launch_generation: PlatformHandle,
    ) -> Result<Self, InstallationError> {
        if prepared.wire != eliot_platform_windows::AGENT_BRIDGE_STAGE_WIRE
            || prepared.wire_version != eliot_platform_windows::AGENT_BRIDGE_STAGE_WIRE_VERSION
        {
            return Err(InstallationError::MigrationRequired {
                reason: "platform agent-bridge stage wire requires explicit re-stage".to_owned(),
            });
        }
        let path_handle = |path: &Path, field: &str| {
            PlatformHandle::new(path.to_string_lossy()).map_err(|error| {
                InstallationError::InvalidField {
                    field: field.to_owned(),
                    reason: error.to_string(),
                }
            })
        };
        let mut value = Self {
            wire: PlatformHandle::new(Self::WIRE).map_err(|error| {
                InstallationError::InvalidField {
                    field: "agent_bridge.stage_prepared.wire".to_owned(),
                    reason: error.to_string(),
                }
            })?,
            installation_id,
            transaction_id: PlatformHandle::new(&prepared.transaction_id)
                .map_err(|error| InstallationError::Platform(error.to_string()))?,
            installation_plan_digest,
            effect_id: PlatformHandle::new(&prepared.effect_id)
                .map_err(|error| InstallationError::Platform(error.to_string()))?,
            request_digest: PlatformHandle::new(&prepared.request_digest)
                .map_err(|error| InstallationError::Platform(error.to_string()))?,
            host_state_root_digest,
            manifest_digest,
            launch_descriptor_digest,
            launch_generation,
            source_path: path_handle(&prepared.source_path, "agent_bridge.source_path")?,
            source_identity: prepared.source_identity,
            source_sha256: PlatformHandle::new(&prepared.source_sha256)
                .map_err(|error| InstallationError::Platform(error.to_string()))?,
            source_size: prepared.source_size,
            temporary_path: path_handle(&prepared.temporary_path, "agent_bridge.temporary_path")?,
            temporary_identity: prepared.temporary_identity,
            destination_path: path_handle(
                &prepared.destination_path,
                "agent_bridge.destination_path",
            )?,
            destination_parent_identity: prepared.parent_identity,
            prepared_digest: PlatformHandle::new("pending")
                .map_err(|error| InstallationError::Platform(error.to_string()))?,
        };
        value.prepared_digest = value.computed_digest()?;
        value.validate()?;
        Ok(value)
    }

    /// Rejects plan, pending-candidate, root, launch, and request substitution.
    pub fn validate_against_phase_b(
        &self,
        intent: &HostPhaseBMaterializationIntent,
        pending: &PendingActivation,
    ) -> Result<(), InstallationError> {
        self.validate()?;
        let source = intent
            .agent_bridge_source
            .as_ref()
            .ok_or(InstallationError::IdentityConflict)?;
        source.validate()?;
        let launch = &pending.manifest.runtime_launch;
        if self.installation_id != launch.installation_epoch.installation
            || self.transaction_id != intent.transaction_id
            || self.installation_plan_digest != intent.installation_plan_digest
            || self.effect_id != intent.effect_id
            || self.request_digest != intent.request_digest
            || self.host_state_root_digest != intent.host_state_root_digest
            || self.manifest_digest != pending.manifest_digest
            || self.launch_descriptor_digest != launch.descriptor_digest
            || self.launch_generation != launch.generation
            || self.source_path != source.source_executable_path
            || self.source_identity != source.source_executable_identity
            || self.source_sha256 != source.source_executable_sha256
            || self.source_size != source.source_executable_size
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// Bridge proof carried by prepared and final Phase-B records. The staged
/// object and content pair are available before publication; security
/// identities/digests remain absent until the provider returns exact retained
/// post-publication readback.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBridgePreparedBinding {
    /// Explicit binding wire discriminator.
    pub wire: PlatformHandle,
    /// Durable pre-publication stage proof.
    pub stage_prepared: AgentBridgeStagePrepared,
    /// Digest of the provider's final staging receipt.
    pub staging_receipt_digest: PlatformHandle,
    /// Exact staged final path.
    pub staged_destination_path: PlatformHandle,
    /// Exact staged final object identity.
    pub staged_destination_identity: FileIdentity,
    /// Exact staged bytes.
    pub staged_sha256: PlatformHandle,
    /// Exact staged byte length.
    pub staged_size: u64,
    /// Protected profile/declaration paths and readback digests.
    pub profile_path: PlatformHandle,
    /// SHA-256 of the protected profile bytes.
    pub profile_digest: PlatformHandle,
    /// Protected static client declaration path.
    pub declaration_path: PlatformHandle,
    /// SHA-256 of the protected declaration bytes.
    pub declaration_digest: PlatformHandle,
    /// Domain-separated digest binding the protected pair.
    pub pair_digest: PlatformHandle,
}

/// Durable identity and descriptor proof for the complete protected contour.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBridgeSecurityContour {
    /// Canonical Host state root path.
    pub host_state_root_path: PlatformHandle,
    /// Identity retained from the root handle.
    pub host_state_root_identity: FileIdentity,
    /// Actual root security descriptor digest.
    pub host_state_root_security_descriptor_digest: PlatformHandle,
    /// Canonical `agent-bridge` child path.
    pub bridge_directory_path: PlatformHandle,
    /// Identity retained from the child handle.
    pub bridge_directory_identity: FileIdentity,
    /// Actual child security descriptor digest.
    pub bridge_directory_security_descriptor_digest: PlatformHandle,
}

impl AgentBridgePreparedBinding {
    /// Current bridge Phase-B binding wire.
    pub const WIRE: &'static str = "eliot.host.agent-bridge-phase-b.v1";

    /// Constructs the binding after exact staged and pair observations.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        stage_prepared: AgentBridgeStagePrepared,
        staging_receipt_digest: PlatformHandle,
        staged_destination_path: PlatformHandle,
        staged_destination_identity: FileIdentity,
        staged_sha256: PlatformHandle,
        staged_size: u64,
        profile_path: PlatformHandle,
        profile_digest: PlatformHandle,
        declaration_path: PlatformHandle,
        declaration_digest: PlatformHandle,
        profile_identity: FileIdentity,
        profile_security_descriptor_digest: PlatformHandle,
        declaration_identity: FileIdentity,
        declaration_security_descriptor_digest: PlatformHandle,
    ) -> Result<Self, InstallationError> {
        let mut value = Self {
            wire: PlatformHandle::new(Self::WIRE).map_err(|error| {
                InstallationError::InvalidField {
                    field: "agent_bridge.binding.wire".to_owned(),
                    reason: error.to_string(),
                }
            })?,
            stage_prepared,
            staging_receipt_digest,
            staged_destination_path,
            staged_destination_identity,
            staged_sha256,
            staged_size,
            profile_path,
            profile_digest,
            declaration_path,
            declaration_digest,
            pair_digest: PlatformHandle::new("pending").map_err(|error| {
                InstallationError::InvalidField {
                    field: "agent_bridge.binding.pair_digest".to_owned(),
                    reason: error.to_string(),
                }
            })?,
        };
        let _ = (
            profile_identity,
            profile_security_descriptor_digest,
            declaration_identity,
            declaration_security_descriptor_digest,
        );
        value.pair_digest = value.computed_pair_digest()?;
        value.validate_prepared()?;
        Ok(value)
    }

    /// Computes the domain-separated profile/declaration pair digest.
    pub fn computed_pair_digest(&self) -> Result<PlatformHandle, InstallationError> {
        let bytes = canonical_json_bytes(&(
            "eliot.host.agent-bridge.profile-declaration-pair.v1\0",
            self.profile_path.as_str(),
            self.profile_digest.as_str(),
            self.declaration_path.as_str(),
            self.declaration_digest.as_str(),
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "agent_bridge.binding.pair_digest".to_owned(),
            reason: error.to_string(),
        })?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
            field: "agent_bridge.binding.pair_digest".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Validates the local stage and protected-pair proof before ACL
    /// convergence. This is not sufficient for a final receipt.
    pub(crate) fn validate_prepared(&self) -> Result<(), InstallationError> {
        if self.wire.as_str() != Self::WIRE {
            return Err(InstallationError::MigrationRequired {
                reason: "agent-bridge Phase-B binding requires explicit re-stage".to_owned(),
            });
        }
        self.stage_prepared.validate()?;
        for (value, field) in [
            (
                &self.staging_receipt_digest,
                "agent_bridge.staging_receipt_digest",
            ),
            (
                &self.staged_destination_path,
                "agent_bridge.staged_destination_path",
            ),
            (&self.profile_path, "agent_bridge.profile_path"),
            (&self.declaration_path, "agent_bridge.declaration_path"),
        ] {
            handle(value, field)?;
        }
        for (value, field) in [
            (
                &self.staging_receipt_digest,
                "agent_bridge.staging_receipt_digest",
            ),
            (&self.staged_sha256, "agent_bridge.staged_sha256"),
            (&self.profile_digest, "agent_bridge.profile_digest"),
            (&self.declaration_digest, "agent_bridge.declaration_digest"),
            (&self.pair_digest, "agent_bridge.pair_digest"),
        ] {
            sha256_handle(value, field)?;
        }
        if self.staged_destination_identity.volume_serial_number == 0
            || self.staged_destination_identity.file_index == 0
            || self.staged_size == 0
            || self.staged_size != self.stage_prepared.source_size
            || self.staged_sha256 != self.stage_prepared.source_sha256
            || self.pair_digest != self.computed_pair_digest()?
        {
            return Err(InstallationError::IdentityConflict);
        }
        if self.staged_destination_path != self.stage_prepared.destination_path {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    /// Validates the prepared binding. A prepared binding cannot be used as a
    /// final receipt because the final type is distinct.
    pub fn validate(&self) -> Result<(), InstallationError> {
        self.validate_prepared()
    }

    /// Attaches provider-owned convergence evidence to the prepared carrier.
    /// Final consumers must still use the dedicated final validation path.
    pub fn with_final_security(
        &self,
        approved_user_sid: &str,
        host_state_root_path: PlatformHandle,
        bridge_directory_path: PlatformHandle,
        receipt: &PlatformAgentBridgeSecurityConvergenceReceipt,
    ) -> Result<AgentBridgePhaseBBinding, InstallationError> {
        AgentBridgePhaseBBinding::from_prepared_security(
            self.clone(),
            approved_user_sid,
            host_state_root_path,
            bridge_directory_path,
            receipt,
        )
    }

    /// Compares immutable prepared fields while ignoring provider ACL proof.
    pub fn matches_prepared_core(&self, prepared: &Self) -> bool {
        self.stage_prepared == prepared.stage_prepared
            && self.staging_receipt_digest == prepared.staging_receipt_digest
            && self.staged_destination_path == prepared.staged_destination_path
            && self.staged_destination_identity == prepared.staged_destination_identity
            && self.staged_sha256 == prepared.staged_sha256
            && self.staged_size == prepared.staged_size
            && self.profile_path == prepared.profile_path
            && self.profile_digest == prepared.profile_digest
            && self.declaration_path == prepared.declaration_path
            && self.declaration_digest == prepared.declaration_digest
    }

    /// Validates all cross-record bindings against the exact pending Phase-B.
    pub fn validate_against_phase_b(
        &self,
        intent: &HostPhaseBMaterializationIntent,
        pending: &PendingActivation,
    ) -> Result<(), InstallationError> {
        self.validate_prepared()?;
        self.stage_prepared
            .validate_against_phase_b(intent, pending)?;
        Ok(())
    }

    /// Joins the platform's prepared capability and final staging receipt
    /// into the installation-owned proof persisted by Host.
    #[allow(clippy::too_many_arguments)]
    pub fn from_platform(
        prepared: &PlatformAgentBridgeStagePrepared,
        receipt: &PlatformAgentBridgeStagingReceipt,
        installation_id: PlatformHandle,
        installation_plan_digest: PlatformHandle,
        host_state_root_digest: PlatformHandle,
        manifest_digest: PlatformHandle,
        launch_descriptor_digest: PlatformHandle,
        launch_generation: PlatformHandle,
        profile_path: PlatformHandle,
        profile_digest: PlatformHandle,
        declaration_path: PlatformHandle,
        declaration_digest: PlatformHandle,
    ) -> Result<Self, InstallationError> {
        if receipt.transaction_id != prepared.transaction_id
            || receipt.effect_id != prepared.effect_id
            || receipt.request_digest != prepared.request_digest
            || receipt.destination_path != prepared.destination_path
            || receipt.temporary_identity != prepared.temporary_identity
            || receipt.sha256 != prepared.source_sha256
            || receipt.size != prepared.source_size
        {
            return Err(InstallationError::IdentityConflict);
        }
        let stage = AgentBridgeStagePrepared::from_platform(
            prepared,
            installation_id,
            installation_plan_digest,
            host_state_root_digest,
            manifest_digest,
            launch_descriptor_digest,
            launch_generation,
        )?;
        let receipt_digest = PlatformHandle::new(receipt.digest())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let destination_path = PlatformHandle::new(receipt.destination_path.to_string_lossy())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let staged_sha256 = PlatformHandle::new(&receipt.sha256)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let mut value = Self {
            wire: PlatformHandle::new(Self::WIRE).map_err(|error| {
                InstallationError::InvalidField {
                    field: "agent_bridge.binding.wire".to_owned(),
                    reason: error.to_string(),
                }
            })?,
            stage_prepared: stage,
            staging_receipt_digest: receipt_digest,
            staged_destination_path: destination_path,
            staged_destination_identity: receipt.destination_identity,
            staged_sha256,
            staged_size: receipt.size,
            profile_path,
            profile_digest,
            declaration_path,
            declaration_digest,
            pair_digest: PlatformHandle::new("pending")
                .map_err(|error| InstallationError::Platform(error.to_string()))?,
        };
        value.pair_digest = value.computed_pair_digest()?;
        value.validate_prepared()?;
        Ok(value)
    }
}

/// Final Agent Bridge Phase-B proof. Unlike the prepared record, this public
/// contract contains no optional security evidence: it can only be formed from
/// a provider convergence receipt and is the sole binding accepted by final
/// receipts and Host projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBridgePhaseBBinding {
    /// Prepared immutable stage/content proof.
    pub prepared: AgentBridgePreparedBinding,
    /// Approved SID from the static profile.
    pub approved_user_sid: PlatformHandle,
    /// Profile object identity and final descriptor digest.
    pub profile_identity: FileIdentity,
    /// Profile descriptor digest observed after convergence.
    pub profile_security_descriptor_digest: PlatformHandle,
    /// Declaration object identity and final descriptor digest.
    pub declaration_identity: FileIdentity,
    /// Declaration descriptor digest observed after convergence.
    pub declaration_security_descriptor_digest: PlatformHandle,
    /// Root/child identity and descriptor contour.
    pub security_contour: AgentBridgeSecurityContour,
    /// Digest binding all prepared and final fields.
    pub pair_digest: PlatformHandle,
}

impl std::ops::Deref for AgentBridgePhaseBBinding {
    type Target = AgentBridgePreparedBinding;

    fn deref(&self) -> &Self::Target {
        &self.prepared
    }
}

impl AgentBridgePhaseBBinding {
    /// Current final bridge binding wire.
    pub const WIRE: &'static str = AgentBridgePreparedBinding::WIRE;

    /// Forms a final proof from the exact retained provider convergence readback.
    pub fn from_prepared_security(
        prepared: AgentBridgePreparedBinding,
        approved_user_sid: &str,
        host_state_root_path: PlatformHandle,
        bridge_directory_path: PlatformHandle,
        receipt: &PlatformAgentBridgeSecurityConvergenceReceipt,
    ) -> Result<Self, InstallationError> {
        let approved_user_sid = PlatformHandle::new(approved_user_sid)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let profile_security_descriptor_digest =
            PlatformHandle::new(&receipt.profile_descriptor_sha256)
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let declaration_security_descriptor_digest =
            PlatformHandle::new(&receipt.declaration_descriptor_sha256)
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let security_contour = AgentBridgeSecurityContour {
            host_state_root_path,
            host_state_root_identity: receipt.host_state_root_identity,
            host_state_root_security_descriptor_digest: PlatformHandle::new(
                &receipt.host_state_root_descriptor_sha256,
            )
            .map_err(|error| InstallationError::Platform(error.to_string()))?,
            bridge_directory_path,
            bridge_directory_identity: receipt.bridge_directory_identity,
            bridge_directory_security_descriptor_digest: PlatformHandle::new(
                &receipt.bridge_directory_descriptor_sha256,
            )
            .map_err(|error| InstallationError::Platform(error.to_string()))?,
        };
        let mut value = Self {
            prepared,
            approved_user_sid,
            profile_identity: receipt.profile_identity,
            profile_security_descriptor_digest,
            declaration_identity: receipt.declaration_identity,
            declaration_security_descriptor_digest,
            security_contour,
            pair_digest: PlatformHandle::new("pending")
                .map_err(|error| InstallationError::Platform(error.to_string()))?,
        };
        value.pair_digest = value.computed_pair_digest()?;
        value.validate()?;
        Ok(value)
    }

    /// Computes the final pair digest.
    pub fn computed_pair_digest(&self) -> Result<PlatformHandle, InstallationError> {
        let bytes = canonical_json_bytes(&(
            "eliot.host.agent-bridge.final-pair.v1\0",
            &self.prepared,
            self.approved_user_sid.as_str(),
            self.profile_identity,
            self.profile_security_descriptor_digest.as_str(),
            self.declaration_identity,
            self.declaration_security_descriptor_digest.as_str(),
            &self.security_contour,
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "agent_bridge.binding.pair_digest".to_owned(),
            reason: error.to_string(),
        })?;
        PlatformHandle::new(sha256_hex(&bytes))
            .map_err(|error| InstallationError::Platform(error.to_string()))
    }

    /// Validates final-only security evidence and its immutable prepared core.
    pub fn validate(&self) -> Result<(), InstallationError> {
        self.prepared.validate_prepared()?;
        if !self.approved_user_sid.as_str().starts_with("S-")
            || self.profile_identity.volume_serial_number == 0
            || self.profile_identity.file_index == 0
            || self.declaration_identity.volume_serial_number == 0
            || self.declaration_identity.file_index == 0
        {
            return Err(InstallationError::IncompleteObservation(
                "Agent Bridge final binding has incomplete identity evidence".to_owned(),
            ));
        }
        sha256_handle(
            &self.profile_security_descriptor_digest,
            "agent_bridge.profile_security_descriptor_digest",
        )?;
        sha256_handle(
            &self.declaration_security_descriptor_digest,
            "agent_bridge.declaration_security_descriptor_digest",
        )?;
        sha256_handle(
            &self
                .security_contour
                .host_state_root_security_descriptor_digest,
            "agent_bridge.security_contour.host_state_root_security_descriptor_digest",
        )?;
        sha256_handle(
            &self
                .security_contour
                .bridge_directory_security_descriptor_digest,
            "agent_bridge.security_contour.bridge_directory_security_descriptor_digest",
        )?;
        sha256_handle(&self.pair_digest, "agent_bridge.binding.pair_digest")?;
        if self.pair_digest != self.computed_pair_digest()? {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    /// Verifies the immutable prepared join without admitting a second final
    /// security record.
    pub fn matches_prepared_core(&self, prepared: &AgentBridgePreparedBinding) -> bool {
        self.prepared == *prepared
    }
}

/// Host-owned durable preparation record for one Phase-B publication.
///
/// The record is committed before the first destination write.  It is the
/// only authority that permits a restarted Host to query-read the four
/// destinations and rehydrate a materialization; destination bytes alone are
/// never adopted as an installation proof.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPhaseBPreparedMaterialization {
    /// Explicit prepared-materialization wire.
    pub wire: PlatformHandle,
    /// Sole installation transaction identity.
    pub transaction_id: PlatformHandle,
    /// Distinct Phase-B materialization effect identity.
    pub effect_id: PlatformHandle,
    /// Prior credential effect identity.
    pub credential_effect_id: PlatformHandle,
    /// Candidate manifest digest.
    pub manifest_digest: PlatformHandle,
    /// Exact Phase-B request digest.
    pub request_digest: PlatformHandle,
    /// Exact credential receipt digest admitted by Phase-B.
    pub credential_receipt_digest: PlatformHandle,
    /// Opaque Host owner epoch challenge.
    pub host_owner_epoch: PlatformHandle,
    /// Host process identity digest.
    pub host_process_identity: PlatformHandle,
    /// SHA-256 digest of the Host process nonce.
    pub host_process_nonce_digest: PlatformHandle,
    /// Host epoch lineage.
    pub host_epoch_lineage: PlatformHandle,
    /// Host epoch sequence.
    pub host_epoch_sequence: u64,
    /// Activation epoch lineage used by the prepared launch contour.
    pub activation_generation_lineage: PlatformHandle,
    /// Activation epoch sequence used by the prepared launch contour.
    pub activation_generation_sequence: u64,
    /// Exact expected authority descriptor digest.
    pub authority_descriptor_digest: PlatformHandle,
    /// Exact expected Store configuration digest.
    pub config_file_digest: PlatformHandle,
    /// Exact expected Store bootstrap descriptor digest.
    pub store_bootstrap_descriptor_digest: PlatformHandle,
    /// Exact expected eliotd descriptor digest.
    pub eliotd_descriptor_digest: PlatformHandle,
    /// Semantic Store configuration hash bound into the bootstrap.
    pub semantic_config_hash: PlatformHandle,
    /// Exact dynamic launch overlay consumed after readback.
    pub launch: RuntimeLaunchDescriptor,
    /// Optional bridge stage/pair proof. `None` preserves legacy Phase-B.
    pub agent_bridge: Option<AgentBridgePreparedBinding>,
    /// Digest of all prepared fields except this digest.
    pub prepared_digest: PlatformHandle,
}

impl HostPhaseBPreparedMaterialization {
    /// Current prepared-materialization wire.
    ///
    /// The owner-epoch identity domain is sequence-bound as of v2. A
    /// persisted v1 preparation therefore cannot be replayed as a current
    /// proof after a Host restart; its discriminator is rejected before any
    /// destination readback or mutation.
    pub const WIRE: &'static str = "eliot.host.phase-b-prepared.v4";

    /// Recomputes the prepared record digest without its self-reference.
    pub fn computed_digest(&self) -> Result<PlatformHandle, InstallationError> {
        let bytes = serde_json::to_vec(&(
            (
                self.wire.as_str(),
                self.transaction_id.as_str(),
                self.effect_id.as_str(),
                self.credential_effect_id.as_str(),
                self.manifest_digest.as_str(),
                self.request_digest.as_str(),
                self.credential_receipt_digest.as_str(),
                self.host_owner_epoch.as_str(),
                self.host_process_identity.as_str(),
                self.host_process_nonce_digest.as_str(),
                self.host_epoch_lineage.as_str(),
            ),
            (
                self.host_epoch_sequence,
                self.activation_generation_lineage.as_str(),
                self.activation_generation_sequence,
                self.authority_descriptor_digest.as_str(),
                self.config_file_digest.as_str(),
                self.store_bootstrap_descriptor_digest.as_str(),
                self.eliotd_descriptor_digest.as_str(),
                self.semantic_config_hash.as_str(),
                &self.launch,
                &self.agent_bridge,
            ),
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "phase_b.prepared_digest".to_owned(),
            reason: error.to_string(),
        })?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
            field: "phase_b.prepared_digest".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Validates the prepared record and every expected destination digest.
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.wire.as_str() != Self::WIRE {
            return Err(InstallationError::InvalidField {
                field: "phase_b.prepared.wire".to_owned(),
                reason: "unsupported prepared-materialization wire".to_owned(),
            });
        }
        for (value, field) in [
            (&self.transaction_id, "phase_b.prepared.transaction_id"),
            (&self.effect_id, "phase_b.prepared.effect_id"),
            (
                &self.credential_effect_id,
                "phase_b.prepared.credential_effect_id",
            ),
            (&self.host_owner_epoch, "phase_b.prepared.host_owner_epoch"),
            (
                &self.host_epoch_lineage,
                "phase_b.prepared.host_epoch_lineage",
            ),
            (
                &self.activation_generation_lineage,
                "phase_b.prepared.activation_generation_lineage",
            ),
        ] {
            handle(value, field)?;
        }
        for (value, field) in [
            (&self.manifest_digest, "phase_b.prepared.manifest_digest"),
            (&self.request_digest, "phase_b.prepared.request_digest"),
            (
                &self.credential_receipt_digest,
                "phase_b.prepared.credential_receipt_digest",
            ),
            (
                &self.host_process_identity,
                "phase_b.prepared.host_process_identity",
            ),
            (
                &self.host_process_nonce_digest,
                "phase_b.prepared.host_process_nonce_digest",
            ),
            (
                &self.authority_descriptor_digest,
                "phase_b.prepared.authority_descriptor_digest",
            ),
            (
                &self.config_file_digest,
                "phase_b.prepared.config_file_digest",
            ),
            (
                &self.store_bootstrap_descriptor_digest,
                "phase_b.prepared.store_bootstrap_descriptor_digest",
            ),
            (
                &self.eliotd_descriptor_digest,
                "phase_b.prepared.eliotd_descriptor_digest",
            ),
            (
                &self.semantic_config_hash,
                "phase_b.prepared.semantic_config_hash",
            ),
            (&self.prepared_digest, "phase_b.prepared.prepared_digest"),
        ] {
            sha256_handle(value, field)?;
        }
        if self.host_epoch_sequence == 0 || self.activation_generation_sequence == 0 {
            return Err(InstallationError::InvalidField {
                field: "phase_b.prepared.epoch_sequence".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        self.launch.validate()?;
        if let Some(bridge) = self.agent_bridge.as_ref() {
            bridge.validate_prepared()?;
        }
        if self.launch.authority_descriptor_digest != self.authority_descriptor_digest
            || self.launch.store_bootstrap_descriptor_digest
                != self.store_bootstrap_descriptor_digest
            || self.launch.eliotd_descriptor_digest != self.eliotd_descriptor_digest
        {
            return Err(InstallationError::IdentityConflict);
        }
        if self.prepared_digest != self.computed_digest()? {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// Exact Host-owned Phase-B proof carried into the pending-to-active CAS.
///
/// The candidate manifest remains immutable and may legitimately retain its
/// Phase-A pending markers. This binding is the separate, post-materialization
/// proof: both physical Phase-B destinations must classify as `Live`, and the
/// Host epoch/nonce and receipt digest must be carried with that readback. The
/// registry validates this proof at the CAS boundary rather than trusting a
/// Host call-site convention.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseBLiveBinding {
    /// Candidate manifest digest whose Phase-B receipt was observed.
    pub manifest_digest: PlatformHandle,
    /// Exact physical SHA-256 read back for the published authority bytes.
    pub authority_descriptor_digest: PlatformHandle,
    /// Exact physical SHA-256 read back for the published Store bootstrap.
    pub store_bootstrap_descriptor_digest: PlatformHandle,
    /// Physical SHA-256 of the materialized Store config bytes.
    pub config_file_digest: PlatformHandle,
    /// Physical SHA-256 of the materialized eliotd descriptor bytes.
    pub eliotd_descriptor_digest: PlatformHandle,
    /// Semantic Store approved-config hash carried by the bootstrap.
    pub semantic_config_hash: PlatformHandle,
    /// Host epoch lineage observed before publication.
    pub host_epoch_lineage: PlatformHandle,
    /// Host epoch sequence observed before publication.
    pub host_epoch_sequence: u64,
    /// SHA-256 digest of the Host process nonce that owns this
    /// materialization. The raw nonce remains only in the `HostStateJournal`
    /// owner and is never copied into the registry terminal.
    pub host_process_nonce_digest: PlatformHandle,
    /// Digest of the complete Host Phase-B receipt/journal binding.
    pub receipt_digest: PlatformHandle,
    /// Phase-B materialization effect identity carried by the public receipt.
    pub effect_id: PlatformHandle,
    /// Digest of the exact `LocalService` credential receipt admitted by
    /// Phase-B; this keeps the credential domain explicit across Host restart.
    pub credential_receipt_digest: PlatformHandle,
    /// Exact Phase-B request digest carried by the public receipt.
    pub request_digest: PlatformHandle,
    /// Host owner epoch digest carried by the public receipt.
    pub host_owner_epoch: PlatformHandle,
    /// Host process identity digest that issued the original materialization.
    pub host_process_identity: PlatformHandle,
    /// Digest of the public, secret-free Phase-B receipt.
    pub public_receipt_digest: PlatformHandle,
    /// Exact installer-provisioned public authority retained after Pending is
    /// consumed, so verifier-only processes never consult ambient state.
    pub provisioned_supervision_authority: ProvisionedSupervisionAuthority,
    /// Final immutable bridge proof retained for active rebinds.
    pub agent_bridge: Option<AgentBridgePhaseBBinding>,
}

impl PhaseBLiveBinding {
    /// Validates the complete physical receipt and public authority binding.
    pub fn validate(&self) -> Result<(), InstallationError> {
        sha256_handle(&self.manifest_digest, "phase_b.manifest_digest")?;
        if phase_b_digest_state(
            &self.authority_descriptor_digest,
            "phase_b.authority_descriptor_digest",
        )? != PhaseBDigestState::Live
        {
            return Err(InstallationError::InvalidField {
                field: "phase_b.authority_descriptor_digest".to_owned(),
                reason: "Phase-B CAS proof must carry an exact live authority readback".to_owned(),
            });
        }
        if phase_b_digest_state(
            &self.store_bootstrap_descriptor_digest,
            "phase_b.store_bootstrap_descriptor_digest",
        )? != PhaseBDigestState::Live
        {
            return Err(InstallationError::InvalidField {
                field: "phase_b.store_bootstrap_descriptor_digest".to_owned(),
                reason: "Phase-B CAS proof must carry an exact live Store bootstrap readback"
                    .to_owned(),
            });
        }
        sha256_handle(&self.config_file_digest, "phase_b.config_file_digest")?;
        sha256_handle(
            &self.eliotd_descriptor_digest,
            "phase_b.eliotd_descriptor_digest",
        )?;
        sha256_handle(&self.semantic_config_hash, "phase_b.semantic_config_hash")?;
        handle(&self.host_epoch_lineage, "phase_b.host_epoch_lineage")?;
        if self.host_epoch_sequence == 0 {
            return Err(InstallationError::InvalidField {
                field: "phase_b.host_epoch_sequence".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        sha256_handle(
            &self.host_process_nonce_digest,
            "phase_b.host_process_nonce_digest",
        )?;
        sha256_handle(&self.receipt_digest, "phase_b.receipt_digest")?;
        handle(&self.effect_id, "phase_b.effect_id")?;
        sha256_handle(
            &self.credential_receipt_digest,
            "phase_b.credential_receipt_digest",
        )?;
        sha256_handle(&self.request_digest, "phase_b.request_digest")?;
        handle(&self.host_owner_epoch, "phase_b.host_owner_epoch")?;
        sha256_handle(&self.host_process_identity, "phase_b.host_process_identity")?;
        sha256_handle(&self.public_receipt_digest, "phase_b.public_receipt_digest")?;
        self.provisioned_supervision_authority
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "phase_b.provisioned_supervision_authority".to_owned(),
                reason: error.to_string(),
            })?;
        if let Some(bridge) = self.agent_bridge.as_ref() {
            bridge.validate()?;
        }
        Ok(())
    }

    /// Returns the exact public authority retained by the active registry
    /// terminal. Consumers must ignore its Kernel-only key reference.
    pub const fn provisioned_supervision_authority(&self) -> &ProvisionedSupervisionAuthority {
        &self.provisioned_supervision_authority
    }
}

/// Durable intent for rebinding a committed Phase-B contour to a fresh Host
/// owner epoch after a Host restart.
///
/// The prior binding is retained as source evidence only.  The current owner
/// and Host epoch fields are the authority for the new publication attempt;
/// destination bytes never participate in constructing this record.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivePhaseBRebindIntent {
    /// Explicit active-rebind operation wire.
    pub wire: PlatformHandle,
    /// Sole installation transaction identity.
    pub transaction_id: PlatformHandle,
    /// Immutable installer plan digest.
    pub plan_digest: PlatformHandle,
    /// Stable operation identity reused across unknown/restart outcomes.
    pub effect_id: PlatformHandle,
    /// Exact approved candidate manifest digest.
    pub manifest_digest: PlatformHandle,
    /// Terminal registry digest for the prior committed activation.
    pub prior_terminal_digest: PlatformHandle,
    /// Prior committed Phase-B public receipt digest, retained as evidence.
    pub prior_phase_b_receipt_digest: PlatformHandle,
    /// Prior Host epoch lineage, retained as evidence only.
    pub prior_host_epoch_lineage: PlatformHandle,
    /// Prior Host epoch sequence, retained as evidence only.
    pub prior_host_epoch_sequence: u64,
    /// Prior Host process nonce digest, retained as evidence only.
    pub prior_host_process_nonce_digest: PlatformHandle,
    /// Prior Host owner epoch digest, retained as evidence only.
    pub prior_host_owner_epoch: PlatformHandle,
    /// Prior Host process identity digest, retained as evidence only.
    pub prior_host_process_identity: PlatformHandle,
    /// Current Host owner epoch capability digest.
    pub host_owner_epoch: PlatformHandle,
    /// Current Host process identity digest.
    pub host_process_identity: PlatformHandle,
    /// Digest of the current Host process nonce.
    pub host_process_nonce_digest: PlatformHandle,
    /// Current Host epoch lineage.
    pub host_epoch_lineage: PlatformHandle,
    /// Current Host epoch sequence.
    pub host_epoch_sequence: u64,
    /// Activation generation lineage for the new live overlay.
    pub activation_generation_lineage: PlatformHandle,
    /// Activation generation sequence for the new live overlay.
    pub activation_generation_sequence: u64,
    /// Immutable Phase-B authority constraint.
    pub static_template: HostPhaseBStaticTemplate,
    /// Digest of the immutable Phase-B authority constraint.
    pub static_template_digest: PlatformHandle,
    /// Digest of all intent fields except this digest.
    pub request_digest: PlatformHandle,
}

impl ActivePhaseBRebindIntent {
    /// Current active-rebind wire discriminator.
    pub const WIRE: &'static str = "eliot.host.phase-b-rebind.v2";

    /// Constructs and validates one current-Host rebind intent from the prior
    /// committed Phase-B binding and the fresh Host owner/epoch evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction_id: PlatformHandle,
        plan_digest: PlatformHandle,
        effect_id: PlatformHandle,
        manifest_digest: PlatformHandle,
        prior_terminal_digest: PlatformHandle,
        prior_binding: &PhaseBLiveBinding,
        host_owner_epoch: PlatformHandle,
        host_process_identity: PlatformHandle,
        host_process_nonce_digest: PlatformHandle,
        host_epoch_lineage: PlatformHandle,
        host_epoch_sequence: u64,
        activation_generation_lineage: PlatformHandle,
        activation_generation_sequence: u64,
        static_template: HostPhaseBStaticTemplate,
    ) -> Result<Self, InstallationError> {
        let static_template_digest = static_template.digest()?;
        let mut value = Self {
            wire: PlatformHandle::new(Self::WIRE).map_err(|error| {
                InstallationError::InvalidField {
                    field: "active_phase_b_rebind.wire".to_owned(),
                    reason: error.to_string(),
                }
            })?,
            transaction_id,
            plan_digest,
            effect_id,
            manifest_digest,
            prior_terminal_digest,
            prior_phase_b_receipt_digest: prior_binding.public_receipt_digest.clone(),
            prior_host_epoch_lineage: prior_binding.host_epoch_lineage.clone(),
            prior_host_epoch_sequence: prior_binding.host_epoch_sequence,
            prior_host_process_nonce_digest: prior_binding.host_process_nonce_digest.clone(),
            prior_host_owner_epoch: prior_binding.host_owner_epoch.clone(),
            prior_host_process_identity: prior_binding.host_process_identity.clone(),
            host_owner_epoch,
            host_process_identity,
            host_process_nonce_digest,
            host_epoch_lineage,
            host_epoch_sequence,
            activation_generation_lineage,
            activation_generation_sequence,
            static_template,
            static_template_digest,
            request_digest: PlatformHandle::new("pending").map_err(|error| {
                InstallationError::InvalidField {
                    field: "active_phase_b_rebind.request_digest".to_owned(),
                    reason: error.to_string(),
                }
            })?,
        };
        value.request_digest = active_phase_b_rebind_intent_digest(&value)?;
        value.validate()?;
        value.validate_against_prior_binding(prior_binding)?;
        Ok(value)
    }

    /// Validates the intent's digest and current/prior owner identity domains.
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.wire.as_str() != Self::WIRE {
            return Err(InstallationError::InvalidField {
                field: "active_phase_b_rebind.wire".to_owned(),
                reason: "unsupported active Phase-B rebind wire".to_owned(),
            });
        }
        for (value, field) in [
            (&self.transaction_id, "active_phase_b_rebind.transaction_id"),
            (&self.effect_id, "active_phase_b_rebind.effect_id"),
            (
                &self.prior_host_epoch_lineage,
                "active_phase_b_rebind.prior_host_epoch_lineage",
            ),
            (
                &self.prior_host_owner_epoch,
                "active_phase_b_rebind.prior_host_owner_epoch",
            ),
            (
                &self.prior_host_process_identity,
                "active_phase_b_rebind.prior_host_process_identity",
            ),
            (
                &self.host_owner_epoch,
                "active_phase_b_rebind.host_owner_epoch",
            ),
            (
                &self.host_epoch_lineage,
                "active_phase_b_rebind.host_epoch_lineage",
            ),
            (
                &self.activation_generation_lineage,
                "active_phase_b_rebind.activation_generation_lineage",
            ),
        ] {
            handle(value, field)?;
        }
        for (value, field) in [
            (&self.plan_digest, "active_phase_b_rebind.plan_digest"),
            (
                &self.manifest_digest,
                "active_phase_b_rebind.manifest_digest",
            ),
            (
                &self.prior_terminal_digest,
                "active_phase_b_rebind.prior_terminal_digest",
            ),
            (
                &self.prior_phase_b_receipt_digest,
                "active_phase_b_rebind.prior_phase_b_receipt_digest",
            ),
            (
                &self.prior_host_process_nonce_digest,
                "active_phase_b_rebind.prior_host_process_nonce_digest",
            ),
            (
                &self.host_process_identity,
                "active_phase_b_rebind.host_process_identity",
            ),
            (
                &self.host_process_nonce_digest,
                "active_phase_b_rebind.host_process_nonce_digest",
            ),
            (
                &self.static_template_digest,
                "active_phase_b_rebind.static_template_digest",
            ),
            (&self.request_digest, "active_phase_b_rebind.request_digest"),
        ] {
            sha256_handle(value, field)?;
        }
        if self.prior_host_epoch_sequence == 0
            || self.host_epoch_sequence == 0
            || self.activation_generation_sequence == 0
        {
            return Err(InstallationError::InvalidField {
                field: "active_phase_b_rebind.epoch_sequence".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        if self.host_epoch_sequence <= self.prior_host_epoch_sequence {
            return Err(InstallationError::InvalidField {
                field: "active_phase_b_rebind.host_epoch_sequence".to_owned(),
                reason: "must be strictly newer than the committed prior Host epoch".to_owned(),
            });
        }
        if self.host_owner_epoch == self.prior_host_owner_epoch
            || self.host_process_identity == self.prior_host_process_identity
            || self.host_process_nonce_digest == self.prior_host_process_nonce_digest
        {
            return Err(InstallationError::IdentityConflict);
        }
        self.static_template.validate()?;
        if self.static_template_digest != self.static_template.digest()? {
            return Err(InstallationError::IdentityConflict);
        }
        if self.request_digest != active_phase_b_rebind_intent_digest(self)? {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    /// Verifies that prior Host/Phase-B fields match the committed source
    /// binding.  In particular, substituting an old nonce or process identity
    /// is rejected before any destination mutation.
    pub fn validate_against_prior_binding(
        &self,
        prior: &PhaseBLiveBinding,
    ) -> Result<(), InstallationError> {
        if self.manifest_digest != prior.manifest_digest
            || self.prior_phase_b_receipt_digest != prior.public_receipt_digest
            || self.prior_host_epoch_lineage != prior.host_epoch_lineage
            || self.prior_host_epoch_sequence != prior.host_epoch_sequence
            || self.prior_host_process_nonce_digest != prior.host_process_nonce_digest
            || self.prior_host_owner_epoch != prior.host_owner_epoch
            || self.prior_host_process_identity != prior.host_process_identity
        {
            return Err(InstallationError::IdentityConflict);
        }
        if self.host_epoch_sequence <= prior.host_epoch_sequence
            || self.host_owner_epoch == prior.host_owner_epoch
            || self.host_process_identity == prior.host_process_identity
            || self.host_process_nonce_digest == prior.host_process_nonce_digest
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

pub(crate) fn active_phase_b_rebind_intent_digest(
    value: &ActivePhaseBRebindIntent,
) -> Result<PlatformHandle, InstallationError> {
    let bytes = serde_json::to_vec(&(
        (
            value.wire.as_str(),
            value.transaction_id.as_str(),
            value.plan_digest.as_str(),
            value.effect_id.as_str(),
            value.manifest_digest.as_str(),
            value.prior_terminal_digest.as_str(),
            value.prior_phase_b_receipt_digest.as_str(),
        ),
        (
            value.prior_host_epoch_lineage.as_str(),
            value.prior_host_epoch_sequence,
            value.prior_host_process_nonce_digest.as_str(),
            value.prior_host_owner_epoch.as_str(),
            value.prior_host_process_identity.as_str(),
            value.host_owner_epoch.as_str(),
            value.host_process_identity.as_str(),
        ),
        (
            value.host_process_nonce_digest.as_str(),
            value.host_epoch_lineage.as_str(),
            value.host_epoch_sequence,
            value.activation_generation_lineage.as_str(),
            value.activation_generation_sequence,
            &value.static_template,
            value.static_template_digest.as_str(),
        ),
    ))
    .map_err(|error| InstallationError::InvalidField {
        field: "active_phase_b_rebind.request_digest".to_owned(),
        reason: error.to_string(),
    })?;
    PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
        field: "active_phase_b_rebind.request_digest".to_owned(),
        reason: error.to_string(),
    })
}

/// Exact receipt written after all four Phase-B destinations are republished
/// under the current Host epoch and read back through no-follow leases.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivePhaseBRebindReceipt {
    /// Explicit receipt wire discriminator.
    pub wire: PlatformHandle,
    /// Sole installation transaction identity.
    pub transaction_id: PlatformHandle,
    /// Stable rebind operation identity.
    pub effect_id: PlatformHandle,
    /// Exact approved candidate manifest digest.
    pub manifest_digest: PlatformHandle,
    /// Exact intent digest that authorized publication.
    pub request_digest: PlatformHandle,
    /// Current Host owner epoch digest.
    pub host_owner_epoch: PlatformHandle,
    /// Current Host process identity digest.
    pub host_process_identity: PlatformHandle,
    /// Current Host process nonce digest.
    pub host_process_nonce_digest: PlatformHandle,
    /// Current Host epoch lineage.
    pub host_epoch_lineage: PlatformHandle,
    /// Current Host epoch sequence.
    pub host_epoch_sequence: u64,
    /// Exact authority descriptor readback digest.
    pub authority_descriptor_digest: PlatformHandle,
    /// Exact Store config readback digest.
    pub config_file_digest: PlatformHandle,
    /// Exact Store bootstrap readback digest.
    pub store_bootstrap_descriptor_digest: PlatformHandle,
    /// Exact eliotd descriptor readback digest.
    pub eliotd_descriptor_digest: PlatformHandle,
    /// Final bridge proof carried through active rebind.
    pub agent_bridge: Option<AgentBridgePhaseBBinding>,
    /// Digest of all receipt fields except this digest.
    pub receipt_digest: PlatformHandle,
}

impl ActivePhaseBRebindReceipt {
    /// Current active-rebind receipt wire discriminator.
    pub const WIRE: &'static str = "eliot.host.phase-b-rebind-receipt.v2";

    /// Constructs an exact receipt from the durable prepared materialization.
    pub fn from_prepared(
        intent: &ActivePhaseBRebindIntent,
        prepared: &HostPhaseBPreparedMaterialization,
    ) -> Result<Self, InstallationError> {
        Self::from_prepared_with_bridge(intent, prepared, None)
    }

    /// Constructs an exact rebind receipt while carrying forward the prior
    /// final Agent Bridge proof when the prepared contour contains one.
    pub fn from_prepared_with_bridge(
        intent: &ActivePhaseBRebindIntent,
        prepared: &HostPhaseBPreparedMaterialization,
        prior_bridge: Option<&AgentBridgePhaseBBinding>,
    ) -> Result<Self, InstallationError> {
        let mut value = Self {
            wire: PlatformHandle::new(Self::WIRE).map_err(|error| {
                InstallationError::InvalidField {
                    field: "active_phase_b_rebind.receipt.wire".to_owned(),
                    reason: error.to_string(),
                }
            })?,
            transaction_id: prepared.transaction_id.clone(),
            effect_id: prepared.effect_id.clone(),
            manifest_digest: prepared.manifest_digest.clone(),
            request_digest: prepared.request_digest.clone(),
            host_owner_epoch: prepared.host_owner_epoch.clone(),
            host_process_identity: prepared.host_process_identity.clone(),
            host_process_nonce_digest: prepared.host_process_nonce_digest.clone(),
            host_epoch_lineage: prepared.host_epoch_lineage.clone(),
            host_epoch_sequence: prepared.host_epoch_sequence,
            authority_descriptor_digest: prepared.authority_descriptor_digest.clone(),
            config_file_digest: prepared.config_file_digest.clone(),
            store_bootstrap_descriptor_digest: prepared.store_bootstrap_descriptor_digest.clone(),
            eliotd_descriptor_digest: prepared.eliotd_descriptor_digest.clone(),
            agent_bridge: prior_bridge.cloned(),
            receipt_digest: PlatformHandle::new("pending").map_err(|error| {
                InstallationError::InvalidField {
                    field: "active_phase_b_rebind.receipt.receipt_digest".to_owned(),
                    reason: error.to_string(),
                }
            })?,
        };
        value.receipt_digest = active_phase_b_rebind_receipt_digest(&value)?;
        value.validate_against(intent, prepared)?;
        Ok(value)
    }

    /// Validates the exact receipt digest and its prepared/current owner bind.
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.wire.as_str() != Self::WIRE {
            return Err(InstallationError::InvalidField {
                field: "active_phase_b_rebind.receipt.wire".to_owned(),
                reason: "unsupported active Phase-B rebind receipt wire".to_owned(),
            });
        }
        for (value, field) in [
            (
                &self.transaction_id,
                "active_phase_b_rebind.receipt.transaction_id",
            ),
            (&self.effect_id, "active_phase_b_rebind.receipt.effect_id"),
            (
                &self.host_owner_epoch,
                "active_phase_b_rebind.receipt.host_owner_epoch",
            ),
            (
                &self.host_epoch_lineage,
                "active_phase_b_rebind.receipt.host_epoch_lineage",
            ),
        ] {
            handle(value, field)?;
        }
        for (value, field) in [
            (
                &self.manifest_digest,
                "active_phase_b_rebind.receipt.manifest_digest",
            ),
            (
                &self.request_digest,
                "active_phase_b_rebind.receipt.request_digest",
            ),
            (
                &self.host_process_identity,
                "active_phase_b_rebind.receipt.host_process_identity",
            ),
            (
                &self.host_process_nonce_digest,
                "active_phase_b_rebind.receipt.host_process_nonce_digest",
            ),
            (
                &self.authority_descriptor_digest,
                "active_phase_b_rebind.receipt.authority_descriptor_digest",
            ),
            (
                &self.config_file_digest,
                "active_phase_b_rebind.receipt.config_file_digest",
            ),
            (
                &self.store_bootstrap_descriptor_digest,
                "active_phase_b_rebind.receipt.store_bootstrap_descriptor_digest",
            ),
            (
                &self.eliotd_descriptor_digest,
                "active_phase_b_rebind.receipt.eliotd_descriptor_digest",
            ),
            (
                &self.receipt_digest,
                "active_phase_b_rebind.receipt.receipt_digest",
            ),
        ] {
            sha256_handle(value, field)?;
        }
        if self.host_epoch_sequence == 0 {
            return Err(InstallationError::InvalidField {
                field: "active_phase_b_rebind.receipt.host_epoch_sequence".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        if let Some(bridge) = self.agent_bridge.as_ref() {
            bridge.validate()?;
        }
        if self.receipt_digest != active_phase_b_rebind_receipt_digest(self)? {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    /// Validates the receipt against the exact intent and durable preparation.
    pub fn validate_against(
        &self,
        intent: &ActivePhaseBRebindIntent,
        prepared: &HostPhaseBPreparedMaterialization,
    ) -> Result<(), InstallationError> {
        self.validate()?;
        prepared.validate()?;
        if intent.validate().is_err()
            || self.transaction_id != intent.transaction_id
            || self.effect_id != intent.effect_id
            || self.manifest_digest != intent.manifest_digest
            || self.request_digest != intent.request_digest
            || self.host_owner_epoch != intent.host_owner_epoch
            || self.host_process_identity != intent.host_process_identity
            || self.host_process_nonce_digest != intent.host_process_nonce_digest
            || self.host_epoch_lineage != intent.host_epoch_lineage
            || self.host_epoch_sequence != intent.host_epoch_sequence
            || self.authority_descriptor_digest != prepared.authority_descriptor_digest
            || self.config_file_digest != prepared.config_file_digest
            || self.store_bootstrap_descriptor_digest != prepared.store_bootstrap_descriptor_digest
            || self.eliotd_descriptor_digest != prepared.eliotd_descriptor_digest
            || self
                .agent_bridge
                .as_ref()
                .map(|bridge| bridge.prepared.clone())
                != prepared.agent_bridge
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

pub(crate) fn active_phase_b_rebind_receipt_digest(
    value: &ActivePhaseBRebindReceipt,
) -> Result<PlatformHandle, InstallationError> {
    let bytes = serde_json::to_vec(&(
        value.wire.as_str(),
        value.transaction_id.as_str(),
        value.effect_id.as_str(),
        value.manifest_digest.as_str(),
        value.request_digest.as_str(),
        value.host_owner_epoch.as_str(),
        value.host_process_identity.as_str(),
        value.host_process_nonce_digest.as_str(),
        value.host_epoch_lineage.as_str(),
        value.host_epoch_sequence,
        value.authority_descriptor_digest.as_str(),
        value.config_file_digest.as_str(),
        value.store_bootstrap_descriptor_digest.as_str(),
        value.eliotd_descriptor_digest.as_str(),
        &value.agent_bridge,
    ))
    .map_err(|error| InstallationError::InvalidField {
        field: "active_phase_b_rebind.receipt.receipt_digest".to_owned(),
        reason: error.to_string(),
    })?;
    PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
        field: "active_phase_b_rebind.receipt.receipt_digest".to_owned(),
        reason: error.to_string(),
    })
}

/// Durable owner-authorized transition that retires one completed active
/// Phase-B rebind attempt after the owning Host died.
///
/// The completed receipt is copied into this record instead of being
/// overwritten.  A fresh direct-child Host can therefore start a new attempt
/// only after this exact transition has won the registry revision CAS.  The
/// transition is evidence, not a destination adoption shortcut: the next
/// intent still has to publish and read back all four Phase-B files under the
/// fresh owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivePhaseBRebindRecovery {
    /// Explicit recovery transition wire discriminator.
    pub wire: PlatformHandle,
    /// Sole installation transaction identity.
    pub transaction_id: PlatformHandle,
    /// Stable rebind operation identity.
    pub effect_id: PlatformHandle,
    /// Exact approved candidate manifest digest.
    pub manifest_digest: PlatformHandle,
    /// Digest of the committed source terminal that authorized the old
    /// attempt.
    pub prior_terminal_digest: PlatformHandle,
    /// Digest of the completed attempt's intent.
    pub prior_request_digest: PlatformHandle,
    /// Digest of the completed attempt's receipt.
    pub prior_receipt_digest: PlatformHandle,
    /// Completed attempt intent retained for forensic validation after the
    /// current lifecycle advances to a fresh owner.
    pub prior_intent: ActivePhaseBRebindIntent,
    /// Completed attempt preparation retained for forensic validation after
    /// the current lifecycle advances to a fresh owner.
    pub prior_prepared: HostPhaseBPreparedMaterialization,
    /// Full completed receipt retained as forensic evidence.
    pub prior_receipt: ActivePhaseBRebindReceipt,
    /// Fresh Host owner epoch authorized to replace the completed attempt.
    pub recovery_host_owner_epoch: PlatformHandle,
    /// Fresh Host process identity authorized to replace the completed attempt.
    pub recovery_host_process_identity: PlatformHandle,
    /// Digest of the fresh Host process nonce.
    pub recovery_host_process_nonce_digest: PlatformHandle,
    /// Fresh Host epoch lineage.
    pub recovery_host_epoch_lineage: PlatformHandle,
    /// Fresh Host epoch sequence.
    pub recovery_host_epoch_sequence: u64,
    /// Digest of every recovery transition field except this digest.
    pub recovery_digest: PlatformHandle,
}

impl ActivePhaseBRebindRecovery {
    /// Current active-rebind recovery transition wire discriminator.
    pub const WIRE: &'static str = "eliot.host.phase-b-rebind-recovery.v2";

    /// Constructs a recovery transition from one exact completed rebind and a
    /// fresh direct-child Host owner.
    pub fn new(
        current: &ActivePhaseBRebind,
        recovery_host_owner_epoch: PlatformHandle,
        recovery_host_process_identity: PlatformHandle,
        recovery_host_process_nonce_digest: PlatformHandle,
        recovery_host_epoch_lineage: PlatformHandle,
        recovery_host_epoch_sequence: u64,
    ) -> Result<Self, InstallationError> {
        current.validate()?;
        let prepared = current.prepared.as_ref().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "active Phase-B recovery requires durable preparation".to_owned(),
            )
        })?;
        let prior_receipt = current.receipt.as_ref().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "active Phase-B recovery requires a completed receipt".to_owned(),
            )
        })?;
        prior_receipt.validate_against(&current.intent, prepared)?;
        let mut value = Self {
            wire: PlatformHandle::new(Self::WIRE).map_err(|error| {
                InstallationError::InvalidField {
                    field: "active_phase_b_rebind.recovery.wire".to_owned(),
                    reason: error.to_string(),
                }
            })?,
            transaction_id: current.intent.transaction_id.clone(),
            effect_id: current.intent.effect_id.clone(),
            manifest_digest: current.intent.manifest_digest.clone(),
            prior_terminal_digest: current.intent.prior_terminal_digest.clone(),
            prior_request_digest: current.intent.request_digest.clone(),
            prior_receipt_digest: prior_receipt.receipt_digest.clone(),
            prior_intent: current.intent.clone(),
            prior_prepared: prepared.clone(),
            prior_receipt: prior_receipt.clone(),
            recovery_host_owner_epoch,
            recovery_host_process_identity,
            recovery_host_process_nonce_digest,
            recovery_host_epoch_lineage,
            recovery_host_epoch_sequence,
            recovery_digest: PlatformHandle::new("pending").map_err(|error| {
                InstallationError::InvalidField {
                    field: "active_phase_b_rebind.recovery.recovery_digest".to_owned(),
                    reason: error.to_string(),
                }
            })?,
        };
        value.recovery_digest = value.computed_digest()?;
        value.validate_against(current)?;
        Ok(value)
    }

    /// Validates the recovery transition's own digest and typed identity
    /// domains. Cross-record bindings are checked by [`Self::validate_against`].
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.wire.as_str() != Self::WIRE {
            return Err(InstallationError::InvalidField {
                field: "active_phase_b_rebind.recovery.wire".to_owned(),
                reason: "unsupported active Phase-B recovery wire".to_owned(),
            });
        }
        for (value, field) in [
            (
                &self.transaction_id,
                "active_phase_b_rebind.recovery.transaction_id",
            ),
            (&self.effect_id, "active_phase_b_rebind.recovery.effect_id"),
            (
                &self.recovery_host_owner_epoch,
                "active_phase_b_rebind.recovery.recovery_host_owner_epoch",
            ),
            (
                &self.recovery_host_epoch_lineage,
                "active_phase_b_rebind.recovery.recovery_host_epoch_lineage",
            ),
        ] {
            handle(value, field)?;
        }
        for (value, field) in [
            (
                &self.manifest_digest,
                "active_phase_b_rebind.recovery.manifest_digest",
            ),
            (
                &self.prior_terminal_digest,
                "active_phase_b_rebind.recovery.prior_terminal_digest",
            ),
            (
                &self.prior_request_digest,
                "active_phase_b_rebind.recovery.prior_request_digest",
            ),
            (
                &self.prior_receipt_digest,
                "active_phase_b_rebind.recovery.prior_receipt_digest",
            ),
            (
                &self.recovery_host_process_identity,
                "active_phase_b_rebind.recovery.recovery_host_process_identity",
            ),
            (
                &self.recovery_host_process_nonce_digest,
                "active_phase_b_rebind.recovery.recovery_host_process_nonce_digest",
            ),
            (
                &self.recovery_digest,
                "active_phase_b_rebind.recovery.recovery_digest",
            ),
        ] {
            sha256_handle(value, field)?;
        }
        self.prior_intent.validate()?;
        self.prior_prepared.validate()?;
        self.prior_receipt
            .validate_against(&self.prior_intent, &self.prior_prepared)?;
        if self.transaction_id != self.prior_intent.transaction_id
            || self.effect_id != self.prior_intent.effect_id
            || self.manifest_digest != self.prior_intent.manifest_digest
            || self.prior_terminal_digest != self.prior_intent.prior_terminal_digest
            || self.prior_request_digest != self.prior_intent.request_digest
            || self.prior_receipt_digest != self.prior_receipt.receipt_digest
        {
            return Err(InstallationError::IdentityConflict);
        }
        if self.recovery_host_epoch_sequence == 0 {
            return Err(InstallationError::InvalidField {
                field: "active_phase_b_rebind.recovery.recovery_host_epoch_sequence".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        self.validate_direct_child_provenance()?;
        if self.recovery_digest != self.computed_digest()? {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    /// Validates that this recovery transition is an exact CAS successor of
    /// the currently durable completed rebind.
    pub fn validate_against(&self, current: &ActivePhaseBRebind) -> Result<(), InstallationError> {
        self.validate()?;
        let prepared = current.prepared.as_ref().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "active Phase-B recovery requires durable preparation".to_owned(),
            )
        })?;
        let receipt = current.receipt.as_ref().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "active Phase-B recovery requires a completed receipt".to_owned(),
            )
        })?;
        receipt.validate_against(&current.intent, prepared)?;
        if self.transaction_id != current.intent.transaction_id
            || self.effect_id != current.intent.effect_id
            || self.manifest_digest != current.intent.manifest_digest
            || self.prior_terminal_digest != current.intent.prior_terminal_digest
            || self.prior_request_digest != current.intent.request_digest
            || self.prior_receipt_digest != receipt.receipt_digest
            || self.prior_intent != current.intent
            || self.prior_prepared != *prepared
            || self.prior_receipt != *receipt
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    fn validate_direct_child_provenance(&self) -> Result<(), InstallationError> {
        let direct_child_sequence = self
            .prior_receipt
            .host_epoch_sequence
            .checked_add(1)
            .ok_or_else(|| InstallationError::InvalidField {
                field: "active_phase_b_rebind.recovery.recovery_host_epoch_sequence".to_owned(),
                reason: "completed Host epoch cannot admit a direct child after sequence overflow"
                    .to_owned(),
            })?;
        if self.recovery_host_epoch_lineage != self.prior_receipt.host_epoch_lineage
            || self.recovery_host_epoch_sequence != direct_child_sequence
            || self.recovery_host_owner_epoch == self.prior_receipt.host_owner_epoch
            || self.recovery_host_process_identity == self.prior_receipt.host_process_identity
            || self.recovery_host_process_nonce_digest
                == self.prior_receipt.host_process_nonce_digest
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    /// Returns whether this transition authorizes the exact successor intent.
    ///
    /// Immutable installation, source-binding, and template fields must be
    /// carried forward byte-for-byte. The Host owner/process contour is taken
    /// only from this recovery transition, while the activation generation is
    /// the exact direct child of the retired attempt.
    #[must_use]
    pub fn authorizes_exact_successor_intent(&self, intent: &ActivePhaseBRebindIntent) -> bool {
        let prior = &self.prior_intent;
        self.transaction_id == intent.transaction_id
            && prior.wire == intent.wire
            && prior.transaction_id == intent.transaction_id
            && prior.plan_digest == intent.plan_digest
            && self.effect_id == intent.effect_id
            && prior.effect_id == intent.effect_id
            && self.manifest_digest == intent.manifest_digest
            && prior.manifest_digest == intent.manifest_digest
            && self.prior_terminal_digest == intent.prior_terminal_digest
            && prior.prior_terminal_digest == intent.prior_terminal_digest
            && prior.prior_phase_b_receipt_digest == intent.prior_phase_b_receipt_digest
            && prior.prior_host_epoch_lineage == intent.prior_host_epoch_lineage
            && prior.prior_host_epoch_sequence == intent.prior_host_epoch_sequence
            && prior.prior_host_process_nonce_digest == intent.prior_host_process_nonce_digest
            && prior.prior_host_owner_epoch == intent.prior_host_owner_epoch
            && prior.prior_host_process_identity == intent.prior_host_process_identity
            && self.recovery_host_owner_epoch == intent.host_owner_epoch
            && self.recovery_host_process_identity == intent.host_process_identity
            && self.recovery_host_process_nonce_digest == intent.host_process_nonce_digest
            && self.recovery_host_epoch_lineage == intent.host_epoch_lineage
            && self.recovery_host_epoch_sequence == intent.host_epoch_sequence
            && prior.activation_generation_lineage == intent.activation_generation_lineage
            && prior.activation_generation_sequence.checked_add(1)
                == Some(intent.activation_generation_sequence)
            && prior.static_template == intent.static_template
            && prior.static_template_digest == intent.static_template_digest
    }

    pub(crate) fn computed_digest(&self) -> Result<PlatformHandle, InstallationError> {
        let bytes = serde_json::to_vec(&(
            self.wire.as_str(),
            self.transaction_id.as_str(),
            self.effect_id.as_str(),
            self.manifest_digest.as_str(),
            self.prior_terminal_digest.as_str(),
            self.prior_request_digest.as_str(),
            self.prior_receipt_digest.as_str(),
            self.prior_intent.request_digest.as_str(),
            self.prior_prepared.prepared_digest.as_str(),
            self.prior_receipt.host_epoch_lineage.as_str(),
            self.prior_receipt.host_epoch_sequence,
            self.recovery_host_owner_epoch.as_str(),
            self.recovery_host_process_identity.as_str(),
            self.recovery_host_process_nonce_digest.as_str(),
            self.recovery_host_epoch_lineage.as_str(),
            self.recovery_host_epoch_sequence,
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "active_phase_b_rebind.recovery.recovery_digest".to_owned(),
            reason: error.to_string(),
        })?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
            field: "active_phase_b_rebind.recovery.recovery_digest".to_owned(),
            reason: error.to_string(),
        })
    }
}

/// Registry-owned Active Phase-B rebind lifecycle.  The intent remains
/// present across every state; prepared and receipt are added only after their
/// exact preceding boundary has committed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivePhaseBRebind {
    /// Durable intent committed before destination mutation.
    pub intent: ActivePhaseBRebindIntent,
    /// Durable preparation committed before destination mutation.
    pub prepared: Option<HostPhaseBPreparedMaterialization>,
    /// Exact no-follow destination readback receipt.
    pub receipt: Option<ActivePhaseBRebindReceipt>,
    /// Completed attempts retired by explicit fresh-owner recovery CAS. These
    /// records are forensic evidence and never become current authority.
    #[serde(default)]
    pub recovery_history: Vec<ActivePhaseBRebindRecovery>,
}

impl ActivePhaseBRebind {
    /// Validates the complete lifecycle and all cross-record bindings.
    pub fn validate(&self) -> Result<(), InstallationError> {
        self.intent.validate()?;
        if let Some(prepared) = self.prepared.as_ref() {
            prepared.validate()?;
            if prepared.transaction_id != self.intent.transaction_id
                || prepared.effect_id != self.intent.effect_id
                || prepared.manifest_digest != self.intent.manifest_digest
                || prepared.request_digest != self.intent.request_digest
                || prepared.host_owner_epoch != self.intent.host_owner_epoch
                || prepared.host_process_identity != self.intent.host_process_identity
                || prepared.host_process_nonce_digest != self.intent.host_process_nonce_digest
                || prepared.host_epoch_lineage != self.intent.host_epoch_lineage
                || prepared.host_epoch_sequence != self.intent.host_epoch_sequence
                || prepared.credential_receipt_digest != self.intent.prior_phase_b_receipt_digest
            {
                return Err(InstallationError::IdentityConflict);
            }
        }
        if let Some(receipt) = self.receipt.as_ref() {
            let prepared = self.prepared.as_ref().ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "active Phase-B rebind receipt has no prepared record".to_owned(),
                )
            })?;
            receipt.validate_against(&self.intent, prepared)?;
        }
        let mut recovery_digests = BTreeSet::new();
        let mut prior_request_digests = BTreeSet::new();
        let mut prior_receipt_digests = BTreeSet::new();
        let mut recovery_owner_epochs = BTreeSet::new();
        let mut recovery_process_identities = BTreeSet::new();
        let mut recovery_nonce_digests = BTreeSet::new();
        let mut previous: Option<&ActivePhaseBRebindRecovery> = None;
        for recovery in &self.recovery_history {
            recovery.validate()?;
            if previous.is_some_and(|prior| {
                !prior.authorizes_exact_successor_intent(&recovery.prior_intent)
            }) || !recovery_digests.insert(recovery.recovery_digest.as_str())
                || !prior_request_digests.insert(recovery.prior_request_digest.as_str())
                || !prior_receipt_digests.insert(recovery.prior_receipt_digest.as_str())
                || !recovery_owner_epochs.insert(recovery.recovery_host_owner_epoch.as_str())
                || !recovery_process_identities
                    .insert(recovery.recovery_host_process_identity.as_str())
                || !recovery_nonce_digests
                    .insert(recovery.recovery_host_process_nonce_digest.as_str())
            {
                return Err(InstallationError::IdentityConflict);
            }
            previous = Some(recovery);
        }
        if previous
            .is_some_and(|recovery| !recovery.authorizes_exact_successor_intent(&self.intent))
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// Typed readiness fence that Host must present at the pending-to-active CAS.
///
/// The fence is an observation binding, not a claim that process liveness is
/// atomic with the registry write. Host must re-probe the Kernel and Store and
/// append the resulting Kernel-authored observation immediately before the CAS.
/// The journal sequence/checksum make that bounded freshness evidence part of
/// the durable idempotency receipt instead of relying on an in-memory lease.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationCommitFence {
    /// Exact approved candidate generation being committed.
    pub generation: PlatformHandle,
    /// Exact approved configuration digest being committed.
    pub config_digest: PlatformHandle,
    /// Physical SHA-256 of the Host Phase-B Store config bytes observed during
    /// readiness. This is intentionally distinct from the immutable Phase-A
    /// template digest above and from Store's semantic approved-config hash.
    pub materialized_config_digest: PlatformHandle,
    /// Exact Host-owned Phase-B authority/bootstrap/epoch proof. This is
    /// separate from the immutable candidate manifest and is mandatory for
    /// every committed activation.
    pub phase_b_live_binding: Option<PhaseBLiveBinding>,
    /// Runtime authority resource generation.
    pub authority_generation: ResourceGeneration,
    /// Runtime authority state fence.
    pub authority_state_fence: StateFence,
    /// SHA-256 checksum of the active durable Kernel record observed by Host.
    pub active_kernel_record_checksum: PlatformHandle,
    /// SHA-256 digest of the Kernel `ProbeReady` request.
    pub probe_request_digest: PlatformHandle,
    /// SHA-256 digest of the Kernel-authored ready receipt.
    pub ready_receipt_digest: PlatformHandle,
    /// Exact Store proof fence returned by the authenticated readiness probe.
    pub store_proof_fence: PlatformHandle,
    /// Digest of the exact Kernel candidate binding used by the probe. This
    /// is a dynamic Host/Kernel contour value; the static manifest cannot
    /// derive process and Job identities, so Host authenticates it through
    /// the fresh Kernel-authored journal observation before this CAS.
    pub candidate_binding_digest: PlatformHandle,
    /// Digest of the exact Store bootstrap requirement used by the probe. The
    /// connection and peer-session portions are dynamic and likewise require
    /// Host's fresh authenticated contour check rather than a manifest-only
    /// reconstruction.
    pub store_requirement_digest: PlatformHandle,
    /// Monotonic Host journal sequence of the fresh readiness observation.
    pub readiness_sequence: u64,
    /// SHA-256 checksum of the journal's final frame at observation time.
    pub readiness_journal_checksum: PlatformHandle,
}

impl ActivationCommitFence {
    /// Validates the self-contained typed fence without asserting process
    /// liveness beyond the supplied durable observation.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.generation, "activation_commit_fence.generation")?;
        sha256_handle(&self.config_digest, "activation_commit_fence.config_digest")?;
        sha256_handle(
            &self.materialized_config_digest,
            "activation_commit_fence.materialized_config_digest",
        )?;
        self.phase_b_live_binding
            .as_ref()
            .ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "activation commit fence is missing the exact Phase-B live binding".to_owned(),
                )
            })?
            .validate()?;
        if self.phase_b_live_binding.as_ref().is_some_and(|binding| {
            binding.config_file_digest != self.materialized_config_digest
                || binding
                    .provisioned_supervision_authority
                    .candidate_generation
                    != self.generation.as_str()
                || binding
                    .provisioned_supervision_authority
                    .authority_generation
                    != self.authority_generation
        }) {
            return Err(InstallationError::IdentityConflict);
        }
        if self.authority_generation.value() == 0 {
            return Err(InstallationError::InvalidField {
                field: "activation_commit_fence.authority_generation".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        self.authority_state_fence
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "activation_commit_fence.authority_state_fence".to_owned(),
                reason: error.to_string(),
            })?;
        if self.authority_state_fence.resource_generation != self.authority_generation {
            return Err(InstallationError::IdentityConflict);
        }
        for (value, field) in [
            (
                &self.active_kernel_record_checksum,
                "activation_commit_fence.active_kernel_record_checksum",
            ),
            (
                &self.probe_request_digest,
                "activation_commit_fence.probe_request_digest",
            ),
            (
                &self.ready_receipt_digest,
                "activation_commit_fence.ready_receipt_digest",
            ),
            (
                &self.candidate_binding_digest,
                "activation_commit_fence.candidate_binding_digest",
            ),
            (
                &self.store_requirement_digest,
                "activation_commit_fence.store_requirement_digest",
            ),
            (
                &self.readiness_journal_checksum,
                "activation_commit_fence.readiness_journal_checksum",
            ),
        ] {
            sha256_handle(value, field)?;
        }
        handle(
            &self.store_proof_fence,
            "activation_commit_fence.store_proof_fence",
        )?;
        if self.readiness_sequence == 0 {
            return Err(InstallationError::InvalidField {
                field: "activation_commit_fence.readiness_sequence".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        Ok(())
    }

    pub(crate) fn validate_against_manifest(
        &self,
        manifest: &CandidateManifest,
    ) -> Result<(), InstallationError> {
        // Candidate and Store contour digests are intentionally not compared
        // to a synthetic manifest value: their process, Job, connection, and
        // peer-session identities are minted at runtime. Host remains the
        // observer for those values and supplies this fence only after the
        // Kernel-authored journal proof and current contour agree. The
        // registry still validates their SHA-256 shape and persists them for
        // exact terminal idempotency comparison.
        self.validate()?;
        let expected_manifest_digest = candidate_manifest_digest(manifest)?;
        let phase_b = self.phase_b_live_binding.as_ref().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "activation commit fence is missing the exact Phase-B live binding".to_owned(),
            )
        })?;
        if phase_b.manifest_digest != expected_manifest_digest {
            return Err(InstallationError::IdentityConflict);
        }
        if self.generation != manifest.generation || self.config_digest != manifest.config_digest {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// An opaque proof that the installation registry has durably committed one
/// exact pending activation.
///
/// The fields and constructor are private on purpose.  A caller can obtain a
/// value only by asking a [`RedbInstallationRegistry`] to read its committed
/// terminal projection.  In particular, serializing a Host-authored
/// [`ActivationCommitFence`] is not sufficient to manufacture this proof.
/// The proof is consumed by the transaction-store reconciliation boundary,
/// which is the only owner allowed to advance the durable transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationCommitReceipt {
    pub(crate) transaction_id: PlatformHandle,
    pub(crate) plan_digest: PlatformHandle,
    pub(crate) generation: PlatformHandle,
    pub(crate) candidate_manifest_digest: PlatformHandle,
    pub(crate) commit_fence: ActivationCommitFence,
    pub(crate) registry_revision: u64,
    pub(crate) terminal_digest: PlatformHandle,
}

impl ActivationCommitReceipt {
    /// Returns the exact installer plan digest authenticated by the terminal.
    #[must_use]
    pub const fn plan_digest(&self) -> &PlatformHandle {
        &self.plan_digest
    }

    /// Returns the exact terminal projection digest for evidence binding.
    #[must_use]
    pub const fn terminal_digest(&self) -> &PlatformHandle {
        &self.terminal_digest
    }

    /// Returns the candidate manifest digest authenticated by the terminal.
    #[must_use]
    pub const fn candidate_manifest_digest(&self) -> &PlatformHandle {
        &self.candidate_manifest_digest
    }

    /// Returns the exact Host-owned readiness fence recorded by the committed
    /// registry terminal.  Callers must still bind this fence to the exact
    /// transaction and generation through this receipt's identity.
    #[must_use]
    pub const fn commit_fence(&self) -> &ActivationCommitFence {
        &self.commit_fence
    }

    pub(crate) fn validate_against_transaction(
        &self,
        transaction: &InstallationTransaction,
    ) -> Result<(), InstallationError> {
        self.commit_fence
            .validate_against_manifest(&transaction.candidate_manifest)?;
        let expected_manifest_digest = candidate_manifest_digest(&transaction.candidate_manifest)?;
        if self.transaction_id != transaction.transaction_id
            || self.plan_digest != transaction.installer_plan_digest
            || self.generation != transaction.candidate_manifest.generation
            || self.candidate_manifest_digest != expected_manifest_digest
        {
            return Err(InstallationError::IdentityConflict);
        }
        sha256_handle(
            &self.terminal_digest,
            "activation_commit_receipt.terminal_digest",
        )?;
        if self.registry_revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "activation_commit_receipt.registry_revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        Ok(())
    }

    pub(crate) fn binding(self) -> ActiveVerifiedReceiptBinding {
        ActiveVerifiedReceiptBinding {
            transaction_id: self.transaction_id,
            plan_digest: self.plan_digest,
            generation: self.generation,
            candidate_manifest_digest: self.candidate_manifest_digest,
            commit_fence: self.commit_fence,
            registry_revision: self.registry_revision,
            terminal_digest: self.terminal_digest,
        }
    }
}

/// The private durable form of [`ActivationCommitReceipt`] retained after the
/// transaction crosses the activation boundary.  It is deliberately part of
/// the v9 transaction wire so a retry can distinguish the exact original
/// registry terminal from a different fence or a stale epoch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActiveVerifiedReceiptBinding {
    pub(crate) transaction_id: PlatformHandle,
    pub(crate) plan_digest: PlatformHandle,
    pub(crate) generation: PlatformHandle,
    pub(crate) candidate_manifest_digest: PlatformHandle,
    pub(crate) commit_fence: ActivationCommitFence,
    pub(crate) registry_revision: u64,
    pub(crate) terminal_digest: PlatformHandle,
}

impl ActiveVerifiedReceiptBinding {
    pub(crate) fn validate_against_transaction(
        &self,
        transaction: &InstallationTransaction,
    ) -> Result<(), InstallationError> {
        let receipt = ActivationCommitReceipt {
            transaction_id: self.transaction_id.clone(),
            plan_digest: self.plan_digest.clone(),
            generation: self.generation.clone(),
            candidate_manifest_digest: self.candidate_manifest_digest.clone(),
            commit_fence: self.commit_fence.clone(),
            registry_revision: self.registry_revision,
            terminal_digest: self.terminal_digest.clone(),
        };
        receipt.validate_against_transaction(transaction)
    }

    pub(crate) fn matches_receipt(&self, receipt: &ActivationCommitReceipt) -> bool {
        self.transaction_id == receipt.transaction_id
            && self.plan_digest == receipt.plan_digest
            && self.generation == receipt.generation
            && self.candidate_manifest_digest == receipt.candidate_manifest_digest
            && self.commit_fence == receipt.commit_fence
            && self.registry_revision == receipt.registry_revision
            && self.terminal_digest == receipt.terminal_digest
    }
}

/// Durable idempotency receipt for the most recent terminal pending
/// activation result.  Keeping the exact transaction and plan bindings lets
/// a retried Host commit/abort return the original terminal result without
/// accepting a different caller after the pending projection is cleared.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingActivationTerminal {
    pub(crate) transaction_id: PlatformHandle,
    pub(crate) plan_digest: PlatformHandle,
    pub(crate) generation: PlatformHandle,
    pub(crate) disposition: PendingActivationTerminalDisposition,
    /// Exact readiness fence used for a committed activation. Aborted
    /// terminals must carry explicit `null` and never a synthetic fence.
    pub(crate) commit_fence: Option<ActivationCommitFence>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum PendingActivationTerminalDisposition {
    Committed,
    Aborted,
}

impl ApprovedGeneration {
    /// Validates the generation and its complete approval binding.
    pub fn validate(&self) -> Result<(), InstallationError> {
        self.manifest.validate()?;
        self.approval.validate()?;
        validate_approval_against_manifest(&self.approval, &self.manifest, "approved_generation")
    }
}

pub(crate) fn validate_approval_against_manifest(
    approval: &InstallationActivationApproval,
    manifest: &CandidateManifest,
    field_prefix: &str,
) -> Result<(), InstallationError> {
    let runtime = &manifest.runtime_launch;
    let expected_manifest_digest = candidate_manifest_digest(manifest)?;
    let matches = [
        approval.generation == manifest.generation,
        approval.candidate_manifest_digest == expected_manifest_digest,
        approval.runtime_descriptor_digest == runtime.descriptor_digest,
        approval.signature_ref == manifest.signature_ref,
        approval.authority_descriptor_path == runtime.authority_descriptor_path,
        approval.authority_descriptor_digest == runtime.authority_descriptor_digest,
        approval.authority_generation == runtime.authority_generation,
        approval.authority_state_fence == runtime.authority_state_fence,
    ];
    if matches.iter().any(|matches| !matches) {
        return Err(InstallationError::InvalidField {
            field: field_prefix.to_owned(),
            reason: "activation approval does not bind the exact candidate manifest".to_owned(),
        });
    }
    Ok(())
}

/// Installation-owned approved-generation and last-known-good registry.
///
/// The registry admits only complete [`CandidateManifest`] values. Activation
/// is a bounded state transition: an unknown generation cannot become active,
/// and rollback selects the previously recorded last-known-good generation.
///
/// ```compile_fail
/// use eliot_installation::ApprovedGenerationRegistry;
/// fn forge_active(registry: &mut ApprovedGenerationRegistry) {
///     registry.active_generation = None;
/// }
/// ```
///
/// The public registry type is also intentionally not deserializable.  Only
/// the private v4 wire decoder can reconstruct an authority projection.
///
/// ```compile_fail
/// use eliot_installation::ApprovedGenerationRegistry;
/// fn forge_registry(bytes: &str) {
///     let _: ApprovedGenerationRegistry = serde_json::from_str(bytes).unwrap();
/// }
/// ```
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedGenerationRegistry {
    /// Mandatory durable wire discriminator.
    pub(crate) registry_wire_version: ContractVersion,
    /// Monotonic CAS revision of this registry projection.
    pub(crate) revision: u64,
    /// Approved generations keyed by their exact generation identity.
    pub(crate) generations: Vec<ApprovedGeneration>,
    /// Installer-owned Host and Watchdog SCM approvals keyed by generation and
    /// role.  This projection is populated only from applied transaction
    /// service effects.
    pub(crate) service_registration_approvals: Vec<InstallerServiceRegistrationApproval>,
    /// Currently active generation identity, when one is active.
    pub(crate) active_generation: Option<PlatformHandle>,
    /// Last-known-good generation identity, when one is available.
    pub(crate) last_known_good_generation: Option<PlatformHandle>,
    /// Installer-owned candidate awaiting Host health proof and commit.
    ///
    /// This field is deliberately required on the wire (rather than given a
    /// serde default).  Registries written before pending activation was
    /// introduced therefore require an explicit migration/re-stage.
    pub(crate) pending_activation: Option<PendingActivation>,
    /// Exact idempotency receipt for the most recent committed or aborted
    /// pending activation.  A new stage supersedes this single terminal
    /// receipt.
    pub(crate) last_terminal_activation: Option<PendingActivationTerminal>,
    /// Host-owned `ActiveVerified` Phase-B rebind lifecycle.  This optional
    /// member is mandatory on the current v10 wire; explicit `null` means no
    /// rebind has ever been attempted.
    pub(crate) active_phase_b_rebind: Option<ActivePhaseBRebind>,
}

impl Default for ApprovedGenerationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn registry_projection_identity(
    registry: &ApprovedGenerationRegistry,
) -> Result<PlatformHandle, InstallationError> {
    let bytes = serde_json::to_vec(registry).map_err(|error| InstallationError::InvalidField {
        field: "activation_projection.registry_identity".to_owned(),
        reason: error.to_string(),
    })?;
    PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
        field: "activation_projection.registry_identity".to_owned(),
        reason: error.to_string(),
    })
}

/// Durable activation candidate handed from the installer coordinator to the
/// Host owner.  Every identity and digest is repeated from the immutable
/// candidate so a stale or substituted pending record fails closed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingActivation {
    /// Sole installation transaction identity.
    pub transaction_id: PlatformHandle,
    /// Digest of the transaction's immutable installer effect plan.
    pub plan_digest: PlatformHandle,
    /// Exact candidate generation and launch contour to be started by Host.
    pub manifest: CandidateManifest,
    /// Candidate configuration digest repeated as an activation binding.
    pub config_digest: PlatformHandle,
    /// Candidate Kernel image digest repeated as an activation binding.
    pub kernel_artifact_digest: PlatformHandle,
    /// Candidate Store bridge image digest repeated as an activation binding.
    pub store_bridge_artifact_digest: PlatformHandle,
    /// Candidate canonical Store image digest repeated as an activation binding.
    pub canonical_store_artifact_digest: PlatformHandle,
    /// Candidate Host executable path repeated as an activation binding.
    pub host_executable_path: PlatformHandle,
    /// Candidate Host image digest repeated as an activation binding.
    pub host_artifact_digest: PlatformHandle,
    /// Candidate mutable-root topology digest repeated as an activation binding.
    pub runtime_state_roots_digest: PlatformHandle,
    /// Canonical digest of `manifest` bytes.
    pub manifest_digest: PlatformHandle,
    /// Prior active generation retained until Host commits this candidate.
    pub prior_active_generation: Option<PlatformHandle>,
    /// Installer approval evidence for this candidate.
    pub approval: InstallationActivationApproval,
    /// Exact secret-free Phase-B intent retained before Host publishes any
    /// destination. Its presence makes an interrupted publication a durable
    /// recovery state rather than an in-memory `HostComposition` fact.
    pub phase_b_intent: Option<HostPhaseBMaterializationIntent>,
    /// Host-owned preparation record committed before the first Phase-B
    /// destination write. It is required for restart readback/adoption.
    pub phase_b_prepared: Option<HostPhaseBPreparedMaterialization>,
    /// Durable prepared receipt, distinct from the final receipt below.
    pub phase_b_prepared_receipt: Option<HostPhaseBPreparedReceipt>,
    /// Durable bridge stage proof committed after the auxiliary `CREATE_NEW`
    /// and before any final publication. It closes the crash/response-loss
    /// window without allowing recovery to adopt foreign bytes.
    pub phase_b_agent_bridge_stage_prepared: Option<AgentBridgeStagePrepared>,
    /// Secret-free Host Phase-B receipt durably persisted before Host starts
    /// the pending generation. This is query/reconcile evidence only; it does
    /// not make the pending registry generation active.
    pub phase_b_receipt: Option<HostPhaseBMaterializationReceipt>,
    /// Durable recovery disposition after an interrupted/failed attempt.
    pub state: PendingActivationState,
}

/// Pending activation disposition.  Recovery-required remains pending and
/// cannot be mistaken for an active generation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum PendingActivationState {
    /// Host may claim and attempt the exact candidate.
    Pending,
    /// A launch or registry outcome is unknown and needs reconciliation.
    RecoveryRequired {
        /// Stable recovery reason without provider secrets.
        reason: String,
    },
}
impl ApprovedGenerationRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            registry_wire_version: INSTALLATION_REGISTRY_WIRE_VERSION,
            revision: 1,
            generations: Vec::new(),
            service_registration_approvals: Vec::new(),
            active_generation: None,
            last_known_good_generation: None,
            pending_activation: None,
            last_terminal_activation: None,
            active_phase_b_rebind: None,
        }
    }

    /// Returns the mandatory durable registry wire version.
    #[must_use]
    pub const fn registry_wire_version(&self) -> ContractVersion {
        self.registry_wire_version
    }

    /// Returns the current monotonic registry CAS revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the exact durable stage proof currently carried by Pending.
    #[must_use]
    pub fn pending_phase_b_agent_bridge_stage_prepared(&self) -> Option<&AgentBridgeStagePrepared> {
        self.pending_activation
            .as_ref()
            .and_then(|pending| pending.phase_b_agent_bridge_stage_prepared.as_ref())
    }

    /// Looks up one exact role approval for a generation without exposing a
    /// mutation seam.
    #[must_use]
    pub fn service_registration_approval(
        &self,
        generation: &PlatformHandle,
        role: InstallerServiceRole,
    ) -> Option<&InstallerServiceRegistrationApproval> {
        self.service_registration_approvals
            .iter()
            .find(|approval| approval.generation == *generation && approval.role == role)
    }

    /// Test-only fixture seam for registry state-machine tests that do not
    /// exercise the production installer transaction. Production admission
    /// is available only through the transaction-bound activation gate.
    #[cfg(test)]
    pub(crate) fn stage_pending_activation(
        &mut self,
        transaction_id: PlatformHandle,
        plan_digest: PlatformHandle,
        manifest: CandidateManifest,
        approval_ref: PlatformHandle,
    ) -> Result<(), InstallationError> {
        if manifest.runtime_launch.profile == InstallationProfile::SystemService {
            return Err(InstallationError::ProfileViolation(
                "SystemService activation requires transaction-bound SCM approvals".to_owned(),
            ));
        }
        let runtime = &manifest.runtime_launch;
        let approval = InstallationActivationApproval {
            approval_ref,
            transaction_id,
            installer_plan_digest: plan_digest,
            generation: manifest.generation.clone(),
            candidate_manifest_digest: candidate_manifest_digest(&manifest)?,
            runtime_descriptor_digest: runtime.descriptor_digest.clone(),
            required_owner: PlatformHandle::new("owner:test").map_err(|error| {
                InstallationError::InvalidField {
                    field: "activation_approval.required_owner".to_owned(),
                    reason: error.to_string(),
                }
            })?,
            signature_ref: manifest.signature_ref.clone(),
            authority_descriptor_path: runtime.authority_descriptor_path.clone(),
            authority_descriptor_digest: runtime.authority_descriptor_digest.clone(),
            authority_generation: runtime.authority_generation,
            authority_state_fence: runtime.authority_state_fence.clone(),
        };
        self.stage_pending_activation_unchecked(manifest, approval, &[])
    }

    pub(crate) fn stage_pending_activation_unchecked(
        &mut self,
        manifest: CandidateManifest,
        approval: InstallationActivationApproval,
        service_registration_approvals: &[InstallerServiceRegistrationApproval],
    ) -> Result<(), InstallationError> {
        self.validate()?;
        if self
            .active_phase_b_rebind
            .as_ref()
            .is_some_and(|rebind| rebind.receipt.is_none())
        {
            return Err(InstallationError::IdentityConflict);
        }
        manifest.validate()?;
        approval.validate()?;
        validate_approval_against_manifest(&approval, &manifest, "pending_activation")?;
        let manifest_digest = candidate_manifest_digest(&manifest)?;
        let pending = PendingActivation {
            transaction_id: approval.transaction_id.clone(),
            plan_digest: approval.installer_plan_digest.clone(),
            config_digest: manifest.config_digest.clone(),
            kernel_artifact_digest: manifest.kernel_artifact_digest.clone(),
            store_bridge_artifact_digest: manifest.store_bridge_artifact_digest.clone(),
            canonical_store_artifact_digest: manifest.canonical_store_artifact_digest.clone(),
            host_executable_path: manifest.host_executable_path.clone(),
            host_artifact_digest: manifest.host_artifact_digest.clone(),
            runtime_state_roots_digest: manifest.runtime_state_roots_digest.clone(),
            manifest,
            manifest_digest,
            prior_active_generation: self.active_generation.clone(),
            approval,
            phase_b_intent: None,
            phase_b_prepared: None,
            phase_b_prepared_receipt: None,
            phase_b_agent_bridge_stage_prepared: None,
            phase_b_receipt: None,
            state: PendingActivationState::Pending,
        };
        if let Some(existing) = &self.pending_activation {
            let mut same_identity = pending.clone();
            same_identity.state = existing.state.clone();
            if existing == &same_identity {
                return Ok(());
            }
            return Err(InstallationError::IdentityConflict);
        }
        if self
            .generations
            .iter()
            .any(|generation| generation.manifest.generation == pending.manifest.generation)
        {
            return Err(InstallationError::Duplicate {
                kind: "approved generation".to_owned(),
                identity: pending.manifest.generation.as_str().to_owned(),
            });
        }
        self.generations.push(ApprovedGeneration {
            manifest: pending.manifest.clone(),
            approval: pending.approval.clone(),
            active: false,
            last_known_good: false,
        });
        self.pending_activation = Some(pending);
        self.service_registration_approvals
            .extend(service_registration_approvals.iter().cloned());
        self.last_terminal_activation = None;
        // A fully receipted ActiveVerified rebind is terminal evidence for the
        // generation that is being superseded. Clear that one-slot projection
        // only after the replacement candidate has passed every staging check.
        // Intent-only or Prepared rebinds remain fail-closed above and cannot
        // be discarded by staging a different generation.
        self.active_phase_b_rebind = None;
        self.validate()
    }

    pub(crate) fn stage_pending_activation_from_transaction_with_approval(
        &mut self,
        transaction: &InstallationTransaction,
        approval: InstallationActivationApproval,
    ) -> Result<(), InstallationError> {
        approval.validate_against(transaction)?;
        let approvals = transaction.service_registration_approvals()?;
        if transaction.profile == InstallationProfile::SystemService && approvals.len() != 2 {
            return Err(InstallationError::IncompleteObservation(
                "SystemService transaction requires exactly Host and Watchdog SCM approvals"
                    .to_owned(),
            ));
        }
        if let Some(existing) = self.pending_activation.as_ref()
            && existing.transaction_id == transaction.transaction_id
            && existing.plan_digest == transaction.installer_plan_digest
            && existing.manifest == transaction.candidate_manifest
            && existing.approval == approval
        {
            for approval in &approvals {
                if self.service_registration_approval(&approval.generation, approval.role)
                    != Some(approval)
                {
                    return Err(InstallationError::IdentityConflict);
                }
            }
            return self.validate();
        }
        self.stage_pending_activation_unchecked(
            transaction.candidate_manifest.clone(),
            approval,
            &approvals,
        )?;
        Ok(())
    }

    pub(crate) fn stage_pending_activation_from_transaction_with_pre_activation_approval(
        &mut self,
        transaction: &InstallationTransaction,
        approval: InstallationActivationApproval,
    ) -> Result<(), InstallationError> {
        transaction.require_signed_pending_activation_effects()?;
        self.stage_pending_activation_from_transaction_with_approval(transaction, approval)
    }

    /// Returns the pending candidate, if one exists.
    #[must_use]
    pub const fn pending_activation(&self) -> Option<&PendingActivation> {
        self.pending_activation.as_ref()
    }

    /// Returns the exact durable public supervision authority for one selected
    /// generation. Pending candidates are exposed only after intent,
    /// preparation and physical receipt all agree on a live Phase-B launch.
    /// Active candidates resolve from the committed fence, or from a fully
    /// receipted active rebind that preserves that exact authority.
    pub fn provisioned_supervision_authority_for_generation(
        &self,
        generation: &PlatformHandle,
    ) -> Result<Option<&ProvisionedSupervisionAuthority>, InstallationError> {
        self.validate()?;
        if let Some(pending) = self
            .pending_activation
            .as_ref()
            .filter(|pending| pending.manifest.generation == *generation)
        {
            let (Some(intent), Some(prepared), Some(receipt)) = (
                pending.phase_b_intent.as_ref(),
                pending.phase_b_prepared.as_ref(),
                pending.phase_b_receipt.as_ref(),
            ) else {
                return Ok(None);
            };
            prepared.launch.require_phase_b_live()?;
            let launch_authority = prepared.launch.provisioned_supervision_authority()?;
            if launch_authority != &intent.provisioned_supervision_authority
                || launch_authority != &receipt.provisioned_supervision_authority
                || launch_authority.candidate_generation != generation.as_str()
            {
                return Err(InstallationError::IdentityConflict);
            }
            return Ok(Some(&receipt.provisioned_supervision_authority));
        }
        if self.active_generation.as_ref() != Some(generation) {
            return Ok(None);
        }
        let committed = self
            .last_committed_activation_fence()
            .and_then(|fence| fence.phase_b_live_binding.as_ref())
            .ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "active generation has no committed Phase-B authority".to_owned(),
                )
            })?;
        let committed_authority = committed.provisioned_supervision_authority();
        if committed_authority.candidate_generation != generation.as_str() {
            return Err(InstallationError::IdentityConflict);
        }
        if let Some(rebind) = self.active_phase_b_rebind.as_ref()
            && rebind.receipt.is_some()
        {
            let rebound_authority = rebind
                .prepared
                .as_ref()
                .ok_or(InstallationError::IdentityConflict)?
                .launch
                .provisioned_supervision_authority()?;
            if rebound_authority != committed_authority {
                return Err(InstallationError::IdentityConflict);
            }
            return Ok(Some(rebound_authority));
        }
        Ok(Some(committed_authority))
    }

    /// Returns the durable `ActiveVerified` Phase-B rebind lifecycle, if one has
    /// been started by the Host owner.
    #[must_use]
    pub fn active_phase_b_rebind(&self) -> Option<&ActivePhaseBRebind> {
        self.active_phase_b_rebind.as_ref()
    }

    pub(crate) fn record_pending_phase_b_receipt_unchecked(
        &mut self,
        receipt: &HostPhaseBMaterializationReceipt,
    ) -> Result<HostPhaseBMaterializationReceipt, InstallationError> {
        self.validate()?;
        let pending = self.pending_activation.as_mut().ok_or_else(|| {
            InstallationError::IncompleteObservation("no pending activation exists".to_owned())
        })?;
        if !matches!(pending.state, PendingActivationState::Pending) {
            return Err(InstallationError::IncompleteObservation(
                "Phase-B receipt requires a pending activation".to_owned(),
            ));
        }
        if pending
            .phase_b_receipt
            .as_ref()
            .is_some_and(|existing| existing != receipt)
        {
            return Err(InstallationError::IdentityConflict);
        }
        let intent = pending
            .phase_b_intent
            .as_ref()
            .ok_or(InstallationError::IdentityConflict)?;
        let prepared_stage = pending.phase_b_agent_bridge_stage_prepared.as_ref();
        match (prepared_stage, receipt.agent_bridge.as_ref()) {
            (None, None) if intent.agent_bridge_source.is_none() => {}
            (Some(stage), Some(bridge))
                if intent.agent_bridge_source.is_some()
                    && bridge.stage_prepared == *stage
                    && bridge.validate_against_phase_b(intent, pending).is_ok() =>
            {
                // The final receipt now retains the exact stage proof; clear
                // only the pre-publication carrier at this terminal boundary.
            }
            _ => return Err(InstallationError::IdentityConflict),
        }
        pending.phase_b_agent_bridge_stage_prepared = None;
        pending.phase_b_prepared_receipt = None;
        pending.phase_b_receipt = Some(receipt.clone());
        let recorded = pending
            .phase_b_receipt
            .clone()
            .ok_or(InstallationError::IdentityConflict)?;
        self.validate()?;
        Ok(recorded)
    }

    pub(crate) fn record_pending_phase_b_prepared_receipt_unchecked(
        &mut self,
        receipt: &HostPhaseBPreparedReceipt,
    ) -> Result<HostPhaseBPreparedReceipt, InstallationError> {
        self.validate()?;
        let pending = self.pending_activation.as_mut().ok_or_else(|| {
            InstallationError::IncompleteObservation("no pending activation exists".to_owned())
        })?;
        if !matches!(pending.state, PendingActivationState::Pending)
            || pending.phase_b_intent.is_none()
            || pending.phase_b_prepared.is_none()
            || pending.phase_b_receipt.is_some()
        {
            return Err(InstallationError::IncompleteObservation(
                "prepared receipt requires pending Phase-B preparation".to_owned(),
            ));
        }
        if pending
            .phase_b_prepared_receipt
            .as_ref()
            .is_some_and(|existing| existing != receipt)
        {
            return Err(InstallationError::IdentityConflict);
        }
        let Some(prepared) = pending.phase_b_prepared.as_ref() else {
            return Err(InstallationError::IdentityConflict);
        };
        let expected_authority = prepared.launch.provisioned_supervision_authority()?;
        if receipt.transaction_id != pending.transaction_id
            || receipt.effect_id != prepared.effect_id
            || receipt.candidate_manifest_digest != prepared.manifest_digest
            || receipt.request_digest != prepared.request_digest
            || receipt.host_owner_epoch != prepared.host_owner_epoch
            || receipt.host_process_identity != prepared.host_process_identity
            || receipt.authority_descriptor_digest != prepared.authority_descriptor_digest
            || receipt.config_file_digest != prepared.config_file_digest
            || receipt.store_bootstrap_descriptor_digest
                != prepared.store_bootstrap_descriptor_digest
            || receipt.eliotd_descriptor_digest != prepared.eliotd_descriptor_digest
            || receipt.provisioned_supervision_authority != *expected_authority
            || receipt.agent_bridge != prepared.agent_bridge
        {
            return Err(InstallationError::IdentityConflict);
        }
        pending.phase_b_prepared_receipt = Some(receipt.clone());
        let recorded = pending
            .phase_b_prepared_receipt
            .clone()
            .ok_or(InstallationError::IdentityConflict)?;
        self.validate()?;
        Ok(recorded)
    }

    pub(crate) fn record_pending_phase_b_intent_unchecked(
        &mut self,
        intent: &HostPhaseBMaterializationIntent,
    ) -> Result<HostPhaseBMaterializationIntent, InstallationError> {
        self.validate()?;
        let pending = self.pending_activation.as_mut().ok_or_else(|| {
            InstallationError::IncompleteObservation("no pending activation exists".to_owned())
        })?;
        if !matches!(pending.state, PendingActivationState::Pending) {
            return Err(InstallationError::IncompleteObservation(
                "Phase-B intent requires a pending activation".to_owned(),
            ));
        }
        if pending
            .phase_b_intent
            .as_ref()
            .is_some_and(|existing| existing != intent)
        {
            return Err(InstallationError::IdentityConflict);
        }
        if pending.phase_b_receipt.is_some() {
            return Err(InstallationError::IdentityConflict);
        }
        pending.phase_b_intent = Some(intent.clone());
        let recorded = pending
            .phase_b_intent
            .clone()
            .ok_or(InstallationError::IdentityConflict)?;
        self.validate()?;
        Ok(recorded)
    }

    pub(crate) fn record_pending_phase_b_prepared_unchecked(
        &mut self,
        prepared: &HostPhaseBPreparedMaterialization,
    ) -> Result<HostPhaseBPreparedMaterialization, InstallationError> {
        self.validate()?;
        let pending = self.pending_activation.as_mut().ok_or_else(|| {
            InstallationError::IncompleteObservation("no pending activation exists".to_owned())
        })?;
        if !matches!(pending.state, PendingActivationState::Pending)
            || pending.phase_b_intent.is_none()
        {
            return Err(InstallationError::IncompleteObservation(
                "Phase-B preparation requires a pending intent".to_owned(),
            ));
        }
        if pending
            .phase_b_prepared
            .as_ref()
            .is_some_and(|existing| existing != prepared)
            || pending.phase_b_receipt.is_some()
        {
            return Err(InstallationError::IdentityConflict);
        }
        pending.phase_b_prepared = Some(prepared.clone());
        let recorded = pending
            .phase_b_prepared
            .clone()
            .ok_or(InstallationError::IdentityConflict)?;
        self.validate()?;
        Ok(recorded)
    }

    pub(crate) fn record_pending_phase_b_agent_bridge_stage_prepared_unchecked(
        &mut self,
        stage: &AgentBridgeStagePrepared,
    ) -> Result<AgentBridgeStagePrepared, InstallationError> {
        self.validate()?;
        let pending = self.pending_activation.as_mut().ok_or_else(|| {
            InstallationError::IncompleteObservation("no pending activation exists".to_owned())
        })?;
        if !matches!(pending.state, PendingActivationState::Pending)
            || pending.phase_b_intent.is_none()
            || pending.phase_b_prepared.is_some()
            || pending.phase_b_receipt.is_some()
        {
            return Err(InstallationError::IncompleteObservation(
                "Agent Bridge stage proof requires an intent before Phase-B preparation".to_owned(),
            ));
        }
        if pending
            .phase_b_agent_bridge_stage_prepared
            .as_ref()
            .is_some_and(|existing| existing != stage)
        {
            return Err(InstallationError::IdentityConflict);
        }
        pending.phase_b_agent_bridge_stage_prepared = Some(stage.clone());
        let recorded = pending
            .phase_b_agent_bridge_stage_prepared
            .clone()
            .ok_or(InstallationError::IdentityConflict)?;
        self.validate()?;
        Ok(recorded)
    }

    pub(crate) fn clear_pending_phase_b_agent_bridge_stage_prepared_unchecked(
        &mut self,
        stage: &AgentBridgeStagePrepared,
    ) -> Result<(), InstallationError> {
        self.validate()?;
        let pending = self.pending_activation.as_mut().ok_or_else(|| {
            InstallationError::IncompleteObservation("no pending activation exists".to_owned())
        })?;
        if pending.phase_b_agent_bridge_stage_prepared.as_ref() != Some(stage)
            || pending.phase_b_prepared.is_some()
            || pending.phase_b_receipt.is_some()
        {
            return Err(InstallationError::IdentityConflict);
        }
        pending.phase_b_agent_bridge_stage_prepared = None;
        self.validate()?;
        Ok(())
    }

    pub(crate) fn clear_pending_phase_b_prepared_unchecked(
        &mut self,
        prepared: &HostPhaseBPreparedMaterialization,
    ) -> Result<(), InstallationError> {
        self.validate()?;
        let pending = self.pending_activation.as_mut().ok_or_else(|| {
            InstallationError::IncompleteObservation("no pending activation exists".to_owned())
        })?;
        if pending.phase_b_prepared.as_ref() != Some(prepared) || pending.phase_b_receipt.is_some()
        {
            return Err(InstallationError::IdentityConflict);
        }
        pending.phase_b_prepared = None;
        self.validate()?;
        Ok(())
    }

    pub(crate) fn clear_pending_phase_b_intent_unchecked(
        &mut self,
        intent: &HostPhaseBMaterializationIntent,
    ) -> Result<(), InstallationError> {
        self.validate()?;
        let pending = self.pending_activation.as_mut().ok_or_else(|| {
            InstallationError::IncompleteObservation("no pending activation exists".to_owned())
        })?;
        if pending.phase_b_intent.as_ref() != Some(intent) || pending.phase_b_receipt.is_some() {
            return Err(InstallationError::IdentityConflict);
        }
        pending.phase_b_intent = None;
        pending.phase_b_agent_bridge_stage_prepared = None;
        self.validate()?;
        Ok(())
    }

    pub(crate) fn validate_active_phase_b_rebind_intent_context(
        &self,
        intent: &ActivePhaseBRebindIntent,
    ) -> Result<(), InstallationError> {
        if self.pending_activation.is_some() {
            return Err(InstallationError::IdentityConflict);
        }
        let active = self.active().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "active Phase-B rebind requires an active generation".to_owned(),
            )
        })?;
        let terminal = self
            .last_terminal_activation
            .as_ref()
            .filter(|terminal| {
                terminal.disposition == PendingActivationTerminalDisposition::Committed
            })
            .ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "active Phase-B rebind requires a committed activation terminal".to_owned(),
                )
            })?;
        let fence = terminal.commit_fence.as_ref().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "active Phase-B rebind requires the committed activation fence".to_owned(),
            )
        })?;
        let prior_binding = fence.phase_b_live_binding.as_ref().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "active Phase-B rebind requires the committed Phase-B binding".to_owned(),
            )
        })?;
        if terminal.transaction_id != intent.transaction_id
            || terminal.plan_digest != intent.plan_digest
            || terminal.generation != active.manifest.generation
            || intent.manifest_digest != candidate_manifest_digest(&active.manifest)?
            || intent.prior_terminal_digest != activation_terminal_digest(terminal)?
        {
            return Err(InstallationError::IdentityConflict);
        }
        intent.validate_against_prior_binding(prior_binding)
    }

    pub(crate) fn record_active_phase_b_rebind_intent_unchecked(
        &mut self,
        intent: &ActivePhaseBRebindIntent,
    ) -> Result<ActivePhaseBRebindIntent, InstallationError> {
        self.validate()?;
        self.validate_active_phase_b_rebind_intent_context(intent)?;
        match self.active_phase_b_rebind.as_ref() {
            None => {
                self.active_phase_b_rebind = Some(ActivePhaseBRebind {
                    intent: intent.clone(),
                    prepared: None,
                    receipt: None,
                    recovery_history: Vec::new(),
                });
            }
            Some(existing) if existing.intent == *intent => {}
            Some(existing)
                if existing.intent.transaction_id == intent.transaction_id
                    && existing.intent.plan_digest == intent.plan_digest
                    && existing.intent.effect_id == intent.effect_id
                    && existing.intent.manifest_digest == intent.manifest_digest
                    && existing.intent.prior_terminal_digest == intent.prior_terminal_digest
                    && existing.intent.prior_phase_b_receipt_digest
                        == intent.prior_phase_b_receipt_digest =>
            {
                if existing.prepared.is_some() && existing.receipt.is_none() {
                    return Err(InstallationError::IdentityConflict);
                }
                if existing.receipt.is_some() || !existing.recovery_history.is_empty() {
                    return Err(InstallationError::IdentityConflict);
                }
                // A fresh Host owner may retry an intent-only operation before
                // any recovery history exists. Completed attempts advance only
                // through the atomic recovery-and-intent transition below, so
                // every retained chain ends at the current authority.
                let recovery_history = existing.recovery_history.clone();
                self.active_phase_b_rebind = Some(ActivePhaseBRebind {
                    intent: intent.clone(),
                    prepared: None,
                    receipt: None,
                    recovery_history,
                });
            }
            Some(_) => return Err(InstallationError::IdentityConflict),
        }
        let recorded = self
            .active_phase_b_rebind
            .as_ref()
            .ok_or(InstallationError::IdentityConflict)?
            .intent
            .clone();
        self.validate()?;
        Ok(recorded)
    }

    pub(crate) fn record_active_phase_b_rebind_recovery_and_intent_unchecked(
        &mut self,
        recovery: &ActivePhaseBRebindRecovery,
        intent: &ActivePhaseBRebindIntent,
    ) -> Result<ActivePhaseBRebind, InstallationError> {
        self.validate()?;
        self.validate_active_phase_b_rebind_intent_context(intent)?;
        let current = self.active_phase_b_rebind.as_ref().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "active Phase-B recovery requires a durable rebind lifecycle".to_owned(),
            )
        })?;
        if current.intent == *intent
            && current
                .recovery_history
                .last()
                .is_some_and(|existing| existing == recovery)
        {
            return Ok(current.clone());
        }
        recovery.validate_against(current)?;
        if !recovery.authorizes_exact_successor_intent(intent) {
            return Err(InstallationError::IdentityConflict);
        }
        if current.recovery_history.iter().any(|existing| {
            existing.recovery_host_owner_epoch == recovery.recovery_host_owner_epoch
                || existing.recovery_host_process_identity
                    == recovery.recovery_host_process_identity
                || existing.recovery_host_process_nonce_digest
                    == recovery.recovery_host_process_nonce_digest
                || existing.recovery_digest == recovery.recovery_digest
                || existing.prior_request_digest == recovery.prior_request_digest
                || existing.prior_receipt_digest == recovery.prior_receipt_digest
        }) {
            return Err(InstallationError::IdentityConflict);
        }
        let rebind = self.active_phase_b_rebind.as_mut().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "active Phase-B recovery requires a durable rebind lifecycle".to_owned(),
            )
        })?;
        rebind.recovery_history.push(recovery.clone());
        rebind.intent = intent.clone();
        rebind.prepared = None;
        rebind.receipt = None;
        let recorded = rebind.clone();
        self.validate()?;
        Ok(recorded)
    }

    pub(crate) fn record_active_phase_b_rebind_prepared_unchecked(
        &mut self,
        prepared: &HostPhaseBPreparedMaterialization,
    ) -> Result<HostPhaseBPreparedMaterialization, InstallationError> {
        self.validate()?;
        let rebind = self.active_phase_b_rebind.as_mut().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "active Phase-B preparation requires a durable rebind intent".to_owned(),
            )
        })?;
        if rebind.receipt.is_some()
            || prepared.transaction_id != rebind.intent.transaction_id
            || prepared.effect_id != rebind.intent.effect_id
            || prepared.manifest_digest != rebind.intent.manifest_digest
            || prepared.request_digest != rebind.intent.request_digest
            || prepared.credential_receipt_digest != rebind.intent.prior_phase_b_receipt_digest
            || prepared.host_owner_epoch != rebind.intent.host_owner_epoch
            || prepared.host_process_identity != rebind.intent.host_process_identity
            || prepared.host_process_nonce_digest != rebind.intent.host_process_nonce_digest
            || prepared.host_epoch_lineage != rebind.intent.host_epoch_lineage
            || prepared.host_epoch_sequence != rebind.intent.host_epoch_sequence
        {
            return Err(InstallationError::IdentityConflict);
        }
        if rebind
            .prepared
            .as_ref()
            .is_some_and(|existing| existing != prepared)
        {
            return Err(InstallationError::IdentityConflict);
        }
        rebind.prepared = Some(prepared.clone());
        let recorded = rebind
            .prepared
            .clone()
            .ok_or(InstallationError::IdentityConflict)?;
        self.validate()?;
        Ok(recorded)
    }

    pub(crate) fn record_active_phase_b_rebind_receipt_unchecked(
        &mut self,
        receipt: &ActivePhaseBRebindReceipt,
    ) -> Result<ActivePhaseBRebindReceipt, InstallationError> {
        self.validate()?;
        let rebind = self.active_phase_b_rebind.as_mut().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "active Phase-B receipt requires a durable rebind intent".to_owned(),
            )
        })?;
        let prepared = rebind.prepared.as_ref().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "active Phase-B receipt requires a durable preparation".to_owned(),
            )
        })?;
        receipt.validate_against(&rebind.intent, prepared)?;
        if rebind
            .receipt
            .as_ref()
            .is_some_and(|existing| existing != receipt)
        {
            return Err(InstallationError::IdentityConflict);
        }
        rebind.receipt = Some(receipt.clone());
        let recorded = rebind
            .receipt
            .clone()
            .ok_or(InstallationError::IdentityConflict)?;
        self.validate()?;
        Ok(recorded)
    }

    pub(crate) fn terminal_matches(
        &self,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: Option<&PlatformHandle>,
        commit_fence: Option<&ActivationCommitFence>,
        disposition: PendingActivationTerminalDisposition,
    ) -> bool {
        self.last_terminal_activation
            .as_ref()
            .is_some_and(|terminal| {
                Self::terminal_identity_matches(
                    terminal,
                    transaction_id,
                    plan_digest,
                    generation,
                    disposition,
                ) && terminal.commit_fence.as_ref() == commit_fence
            })
    }

    pub(crate) fn terminal_identity_matches(
        terminal: &PendingActivationTerminal,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: Option<&PlatformHandle>,
        disposition: PendingActivationTerminalDisposition,
    ) -> bool {
        terminal.transaction_id == *transaction_id
            && terminal.plan_digest == *plan_digest
            && generation.is_none_or(|value| terminal.generation == *value)
            && terminal.disposition == disposition
    }

    /// Host-only claim/retry transition for one exact pending identity.
    ///
    /// The capability is minted only by the live Host owner lease. An external
    /// installer or plugin cannot call this method without that proof.
    ///
    /// ```compile_fail
    /// # use eliot_installation::ApprovedGenerationRegistry;
    /// # use eliot_platform::PlatformHandle;
    /// # let mut registry = ApprovedGenerationRegistry::new();
    /// # let transaction = PlatformHandle::new("tx").unwrap();
    /// # let plan = PlatformHandle::new("plan").unwrap();
    /// # let generation = PlatformHandle::new("generation").unwrap();
    /// registry.claim_pending_activation(&transaction, &plan, &generation);
    /// ```
    /// Recovery-required records may be retried with the same transaction and
    /// plan digest; substitutions are rejected before any process launch.
    #[cfg(test)]
    pub(crate) fn claim_pending_activation(
        &mut self,
        host: &HostOwnerEpochCapability,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: &PlatformHandle,
    ) -> Result<PendingActivation, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.claim_pending_activation_unchecked(transaction_id, plan_digest, generation)
    }

    pub(crate) fn claim_pending_activation_unchecked(
        &mut self,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: &PlatformHandle,
    ) -> Result<PendingActivation, InstallationError> {
        self.validate()?;
        let pending = self.pending_activation.as_mut().ok_or_else(|| {
            InstallationError::IncompleteObservation("no pending activation exists".to_owned())
        })?;
        if pending.transaction_id != *transaction_id
            || pending.plan_digest != *plan_digest
            || pending.manifest.generation != *generation
        {
            return Err(InstallationError::IdentityConflict);
        }
        pending.state = PendingActivationState::Pending;
        let claimed = pending.clone();
        self.validate()?;
        Ok(claimed)
    }

    /// Returns the immutable approved-generation projection.
    #[must_use]
    pub fn generations(&self) -> &[ApprovedGeneration] {
        &self.generations
    }

    /// Returns the active generation identity, if committed by Host.
    #[must_use]
    pub const fn active_generation(&self) -> Option<&PlatformHandle> {
        self.active_generation.as_ref()
    }

    /// Returns the retained last-known-good identity, if any.
    #[must_use]
    pub const fn last_known_good_generation(&self) -> Option<&PlatformHandle> {
        self.last_known_good_generation.as_ref()
    }

    /// Commits a Host-proven healthy pending candidate and clears pending.
    /// The transaction and plan digest are mandatory idempotency bindings.
    #[cfg(test)]
    pub(crate) fn commit_pending_activation(
        &mut self,
        host: &HostOwnerEpochCapability,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: &PlatformHandle,
        commit_fence: &ActivationCommitFence,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.commit_pending_activation_unchecked(
            transaction_id,
            plan_digest,
            generation,
            commit_fence,
        )
    }

    pub(crate) fn commit_pending_activation_unchecked(
        &mut self,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: &PlatformHandle,
        commit_fence: &ActivationCommitFence,
    ) -> Result<(), InstallationError> {
        self.validate()?;
        commit_fence.validate()?;
        let Some(pending) = self.pending_activation.as_ref() else {
            if self.terminal_matches(
                transaction_id,
                plan_digest,
                Some(generation),
                Some(commit_fence),
                PendingActivationTerminalDisposition::Committed,
            ) {
                return Ok(());
            }
            if self
                .last_terminal_activation
                .as_ref()
                .is_some_and(|terminal| {
                    Self::terminal_identity_matches(
                        terminal,
                        transaction_id,
                        plan_digest,
                        Some(generation),
                        PendingActivationTerminalDisposition::Committed,
                    )
                })
            {
                return Err(InstallationError::IdentityConflict);
            }
            return Err(InstallationError::IncompleteObservation(
                "no pending activation exists".to_owned(),
            ));
        };
        if pending.transaction_id != *transaction_id
            || pending.plan_digest != *plan_digest
            || pending.manifest.generation != *generation
        {
            return Err(InstallationError::IdentityConflict);
        }
        if !matches!(pending.state, PendingActivationState::Pending) {
            return Err(InstallationError::IncompleteObservation(
                "pending activation requires recovery before commit".to_owned(),
            ));
        }
        commit_fence.validate_against_manifest(&pending.manifest)?;
        let pending_record = pending.clone();
        let pending = self.pending_activation.take();
        if let Err(error) = self.activate(generation) {
            self.pending_activation = pending;
            return Err(error);
        }
        self.last_terminal_activation = Some(PendingActivationTerminal {
            transaction_id: pending_record.transaction_id,
            plan_digest: pending_record.plan_digest,
            generation: pending_record.manifest.generation,
            disposition: PendingActivationTerminalDisposition::Committed,
            commit_fence: Some(commit_fence.clone()),
        });
        self.validate()
    }

    /// Records an unknown/failed Host attempt without advertising the candidate.
    #[cfg(test)]
    pub(crate) fn mark_pending_recovery(
        &mut self,
        host: &HostOwnerEpochCapability,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        reason: impl Into<String>,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.mark_pending_recovery_unchecked(transaction_id, plan_digest, reason)
    }

    pub(crate) fn mark_pending_recovery_unchecked(
        &mut self,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        reason: impl Into<String>,
    ) -> Result<(), InstallationError> {
        self.validate()?;
        let pending = self.pending_activation.as_mut().ok_or_else(|| {
            InstallationError::IncompleteObservation("no pending activation exists".to_owned())
        })?;
        if pending.transaction_id != *transaction_id || pending.plan_digest != *plan_digest {
            return Err(InstallationError::IdentityConflict);
        }
        let reason = reason.into();
        text(&reason, "pending_activation.state.reason")?;
        pending.state = PendingActivationState::RecoveryRequired { reason };
        self.validate()
    }

    /// Aborts a first-install candidate without creating an active/LKG state.
    #[cfg(test)]
    pub(crate) fn abort_pending_activation(
        &mut self,
        host: &HostOwnerEpochCapability,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.abort_pending_activation_unchecked(transaction_id, plan_digest)
    }

    pub(crate) fn abort_pending_activation_unchecked(
        &mut self,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        self.validate()?;
        let Some(pending) = self.pending_activation.as_ref() else {
            if self.terminal_matches(
                transaction_id,
                plan_digest,
                None,
                None,
                PendingActivationTerminalDisposition::Aborted,
            ) {
                return Ok(());
            }
            return Err(InstallationError::IncompleteObservation(
                "no pending activation exists".to_owned(),
            ));
        };
        if pending.transaction_id != *transaction_id || pending.plan_digest != *plan_digest {
            return Err(InstallationError::IdentityConflict);
        }
        if self.active_generation.is_some() || self.last_known_good_generation.is_some() {
            return Err(InstallationError::IncompleteObservation(
                "abort-to-none is only valid for first install".to_owned(),
            ));
        }
        let generation = pending.manifest.generation.clone();
        let terminal = PendingActivationTerminal {
            transaction_id: pending.transaction_id.clone(),
            plan_digest: pending.plan_digest.clone(),
            generation: generation.clone(),
            disposition: PendingActivationTerminalDisposition::Aborted,
            commit_fence: None,
        };
        self.generations
            .retain(|item| item.manifest.generation != generation);
        self.service_registration_approvals
            .retain(|approval| approval.generation != generation);
        self.pending_activation = None;
        self.last_terminal_activation = Some(terminal);
        self.validate()
    }

    /// Activates an approved generation and records the prior active
    /// generation as last-known-good before crossing the activation boundary.
    pub(crate) fn activate(
        &mut self,
        generation: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        self.validate()?;
        let selected = self
            .generations
            .iter()
            .position(|item| &item.manifest.generation == generation)
            .ok_or_else(|| {
                InstallationError::IncompleteObservation("generation is not approved".to_owned())
            })?;
        if self.active_generation.as_ref() == Some(generation) {
            // Reactivation is idempotent, but still requires the full
            // projection to be internally consistent.
            return Ok(());
        }
        let previous = self.active_generation.take();
        self.last_known_good_generation.clone_from(&previous);
        for item in &mut self.generations {
            item.active = false;
            // A cutover has exactly one LKG: the generation that was active
            // immediately before this transition.  Clear any stale marker
            // before setting that projection below.
            item.last_known_good = false;
        }
        if let Some(previous) = previous
            && let Some(item) = self
                .generations
                .iter_mut()
                .find(|item| item.manifest.generation == previous)
        {
            item.last_known_good = true;
        }
        self.generations[selected].active = true;
        self.generations[selected].last_known_good = false;
        self.active_generation = Some(generation.clone());
        self.validate()?;
        Ok(())
    }

    /// Returns the currently active approved generation.
    #[must_use]
    pub fn active(&self) -> Option<&ApprovedGeneration> {
        self.active_generation.as_ref().and_then(|generation| {
            self.generations
                .iter()
                .find(|item| &item.manifest.generation == generation && item.active)
        })
    }

    /// Returns the exact fence recorded for the most recent committed
    /// activation, if the terminal receipt is a committed disposition.
    #[must_use]
    pub fn last_committed_activation_fence(&self) -> Option<&ActivationCommitFence> {
        self.last_terminal_activation.as_ref().and_then(|terminal| {
            (terminal.disposition == PendingActivationTerminalDisposition::Committed)
                .then_some(terminal.commit_fence.as_ref())
                .flatten()
        })
    }

    pub(crate) fn validate_terminal_activation(
        &self,
        terminal: &PendingActivationTerminal,
    ) -> Result<(), InstallationError> {
        handle(
            &terminal.transaction_id,
            "last_terminal_activation.transaction_id",
        )?;
        sha256_handle(
            &terminal.plan_digest,
            "last_terminal_activation.plan_digest",
        )?;
        handle(&terminal.generation, "last_terminal_activation.generation")?;
        match terminal.disposition {
            PendingActivationTerminalDisposition::Committed => {
                if self.active_generation.as_ref() != Some(&terminal.generation) {
                    return Err(InstallationError::IncompleteObservation(
                        "committed terminal activation is not the active generation".to_owned(),
                    ));
                }
                let Some(commit_fence) = terminal.commit_fence.as_ref() else {
                    return Err(InstallationError::IncompleteObservation(
                        "committed terminal activation is missing its readiness fence".to_owned(),
                    ));
                };
                let manifest = self
                    .generations
                    .iter()
                    .find(|item| item.manifest.generation == terminal.generation)
                    .ok_or_else(|| {
                        InstallationError::IncompleteObservation(
                            "committed terminal activation generation is not approved".to_owned(),
                        )
                    })?;
                commit_fence.validate_against_manifest(&manifest.manifest)
            }
            PendingActivationTerminalDisposition::Aborted => {
                if terminal.commit_fence.is_some() {
                    return Err(InstallationError::IncompleteObservation(
                        "aborted terminal activation carries a readiness fence".to_owned(),
                    ));
                }
                if self
                    .generations
                    .iter()
                    .any(|item| item.manifest.generation == terminal.generation)
                {
                    return Err(InstallationError::IncompleteObservation(
                        "aborted terminal activation remains approved".to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Validates the complete registry projection and all generation entries.
    #[allow(
        clippy::too_many_lines,
        reason = "registry validation keeps the complete activation authority in one boundary"
    )]
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.registry_wire_version != INSTALLATION_REGISTRY_WIRE_VERSION {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "approved-generation registry wire {} cannot be read as {}",
                    self.registry_wire_version, INSTALLATION_REGISTRY_WIRE_VERSION
                ),
            });
        }
        if self.revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "registry.revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        let mut identities = BTreeSet::new();
        let mut service_identities = BTreeSet::new();
        let mut active_count = 0_usize;
        let mut lkg_count = 0_usize;
        for generation in &self.generations {
            generation.validate()?;
            if !identities.insert(generation.manifest.generation.as_str()) {
                return Err(InstallationError::Duplicate {
                    kind: "approved generation".to_owned(),
                    identity: generation.manifest.generation.as_str().to_owned(),
                });
            }
            if generation.active {
                active_count += 1;
            }
            if generation.last_known_good {
                lkg_count += 1;
            }
        }
        for approval in &self.service_registration_approvals {
            approval.validate()?;
            let generation = self
                .generations
                .iter()
                .find(|item| item.manifest.generation == approval.generation)
                .ok_or(InstallationError::IdentityConflict)?;
            if generation.manifest.runtime_launch.profile != InstallationProfile::SystemService {
                return Err(InstallationError::ProfileViolation(
                    "SCM registration approvals require the SystemService profile".to_owned(),
                ));
            }
            if !service_identities.insert((&approval.generation, approval.role)) {
                return Err(InstallationError::Duplicate {
                    kind: "service registration approval".to_owned(),
                    identity: format!("{}:{:?}", approval.generation.as_str(), approval.role),
                });
            }
        }
        for generation in &self.generations {
            if generation.manifest.runtime_launch.profile == InstallationProfile::SystemService {
                let count = self
                    .service_registration_approvals
                    .iter()
                    .filter(|approval| approval.generation == generation.manifest.generation)
                    .count();
                if count != 2 {
                    return Err(InstallationError::IncompleteObservation(
                        "SystemService generation requires exactly Host and Watchdog SCM approvals"
                            .to_owned(),
                    ));
                }
            }
        }
        if active_count > 1 {
            return Err(InstallationError::IncompleteObservation(
                "registry contains multiple active generations".to_owned(),
            ));
        }
        if lkg_count > 1 {
            return Err(InstallationError::IncompleteObservation(
                "registry contains multiple last-known-good generations".to_owned(),
            ));
        }
        if let Some(active) = &self.active_generation {
            if active_count != 1
                || !self
                    .generations
                    .iter()
                    .any(|item| item.active && item.manifest.generation == *active)
            {
                return Err(InstallationError::IncompleteObservation(
                    "active generation is absent from registry".to_owned(),
                ));
            }
        } else if active_count != 0 {
            return Err(InstallationError::IncompleteObservation(
                "active generation flag has no registry identity".to_owned(),
            ));
        }
        if let Some(lkg) = &self.last_known_good_generation {
            if lkg_count != 1
                || !self
                    .generations
                    .iter()
                    .any(|item| item.last_known_good && item.manifest.generation == *lkg)
            {
                return Err(InstallationError::IncompleteObservation(
                    "last-known-good generation is absent from registry".to_owned(),
                ));
            }
            if self.active_generation.as_ref() == Some(lkg) {
                return Err(InstallationError::IncompleteObservation(
                    "active generation cannot also be last-known-good".to_owned(),
                ));
            }
        } else if lkg_count != 0 {
            return Err(InstallationError::IncompleteObservation(
                "last-known-good flag has no registry identity".to_owned(),
            ));
        }
        if let Some(terminal) = &self.last_terminal_activation {
            self.validate_terminal_activation(terminal)?;
        }
        if self.pending_activation.is_some() && self.active_phase_b_rebind.is_some() {
            return Err(InstallationError::IdentityConflict);
        }
        if let Some(pending) = &self.pending_activation {
            pending.validate(self.active_generation.as_ref())?;
            if !self
                .generations
                .iter()
                .any(|item| item.manifest == pending.manifest && item.approval == pending.approval)
            {
                return Err(InstallationError::IncompleteObservation(
                    "pending activation candidate is absent from registry".to_owned(),
                ));
            }
        }
        if let Some(rebind) = self.active_phase_b_rebind.as_ref() {
            rebind.validate()?;
            let active = self.active().ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "active Phase-B rebind has no active approved generation".to_owned(),
                )
            })?;
            let terminal = self
                .last_terminal_activation
                .as_ref()
                .filter(|terminal| {
                    terminal.disposition == PendingActivationTerminalDisposition::Committed
                })
                .ok_or_else(|| {
                    InstallationError::IncompleteObservation(
                        "active Phase-B rebind has no committed source terminal".to_owned(),
                    )
                })?;
            let fence = terminal.commit_fence.as_ref().ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "active Phase-B rebind source terminal has no fence".to_owned(),
                )
            })?;
            let prior_binding = fence.phase_b_live_binding.as_ref().ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "active Phase-B rebind source terminal has no Phase-B binding".to_owned(),
                )
            })?;
            let terminal_digest = activation_terminal_digest(terminal)?;
            if terminal.transaction_id != rebind.intent.transaction_id
                || terminal.plan_digest != rebind.intent.plan_digest
                || terminal.generation != active.manifest.generation
                || rebind.intent.manifest_digest != candidate_manifest_digest(&active.manifest)?
                || rebind.intent.prior_terminal_digest != terminal_digest
            {
                return Err(InstallationError::IdentityConflict);
            }
            rebind
                .intent
                .validate_against_prior_binding(prior_binding)?;
            if let Some(prepared) = rebind.prepared.as_ref() {
                prepared.launch.require_phase_b_live()?;
                if prepared.launch.provisioned_supervision_authority()?
                    != prior_binding.provisioned_supervision_authority()
                {
                    return Err(InstallationError::IdentityConflict);
                }
            }
            for recovery in &rebind.recovery_history {
                if recovery.prior_terminal_digest != terminal_digest {
                    return Err(InstallationError::IdentityConflict);
                }
                recovery
                    .prior_intent
                    .validate_against_prior_binding(prior_binding)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn candidate_manifest_digest(
    manifest: &CandidateManifest,
) -> Result<PlatformHandle, InstallationError> {
    let bytes = serde_json::to_vec(manifest).map_err(|error| InstallationError::InvalidField {
        field: "pending_activation.manifest_digest".to_owned(),
        reason: error.to_string(),
    })?;
    PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
        field: "pending_activation.manifest_digest".to_owned(),
        reason: error.to_string(),
    })
}

pub(crate) fn activation_terminal_digest(
    terminal: &PendingActivationTerminal,
) -> Result<PlatformHandle, InstallationError> {
    let bytes =
        serde_json::to_vec(terminal).map_err(|error| InstallationError::CorruptRegistry {
            reason: format!("committed activation terminal could not be canonicalized: {error}"),
        })?;
    PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
        field: "activation_commit_receipt.terminal_digest".to_owned(),
        reason: error.to_string(),
    })
}
impl PendingActivation {
    #[allow(
        clippy::too_many_lines,
        reason = "pending activation validation keeps every manifest, Phase-B intent, receipt, and state binding together"
    )]
    fn validate(
        &self,
        active_generation: Option<&PlatformHandle>,
    ) -> Result<(), InstallationError> {
        handle(&self.transaction_id, "pending_activation.transaction_id")?;
        sha256_handle(&self.plan_digest, "pending_activation.plan_digest")?;
        self.manifest.validate()?;
        sha256_handle(&self.manifest_digest, "pending_activation.manifest_digest")?;
        if candidate_manifest_digest(&self.manifest)? != self.manifest_digest {
            return Err(InstallationError::IdentityConflict);
        }
        for (value, field, expected) in [
            (
                &self.config_digest,
                "config_digest",
                &self.manifest.config_digest,
            ),
            (
                &self.kernel_artifact_digest,
                "kernel_artifact_digest",
                &self.manifest.kernel_artifact_digest,
            ),
            (
                &self.store_bridge_artifact_digest,
                "store_bridge_artifact_digest",
                &self.manifest.store_bridge_artifact_digest,
            ),
            (
                &self.canonical_store_artifact_digest,
                "canonical_store_artifact_digest",
                &self.manifest.canonical_store_artifact_digest,
            ),
            (
                &self.host_artifact_digest,
                "host_artifact_digest",
                &self.manifest.host_artifact_digest,
            ),
            (
                &self.runtime_state_roots_digest,
                "runtime_state_roots_digest",
                &self.manifest.runtime_state_roots_digest,
            ),
        ] {
            sha256_handle(value, &format!("pending_activation.{field}"))?;
            if value != expected {
                return Err(InstallationError::IdentityConflict);
            }
        }
        if self.host_executable_path != self.manifest.host_executable_path {
            return Err(InstallationError::IdentityConflict);
        }
        if let Some(prior) = &self.prior_active_generation {
            handle(prior, "pending_activation.prior_active_generation")?;
        }
        if self.prior_active_generation.as_ref() != active_generation {
            return Err(InstallationError::IdentityConflict);
        }
        self.approval.validate()?;
        if self.transaction_id != self.approval.transaction_id
            || self.plan_digest != self.approval.installer_plan_digest
        {
            return Err(InstallationError::IdentityConflict);
        }
        validate_approval_against_manifest(&self.approval, &self.manifest, "pending_activation")?;
        if self.manifest_digest != self.approval.candidate_manifest_digest {
            return Err(InstallationError::IdentityConflict);
        }
        if let Some(intent) = &self.phase_b_intent {
            if self.manifest.runtime_launch.profile != InstallationProfile::SystemService {
                return Err(InstallationError::ProfileViolation(
                    "Phase-B intent requires the SystemService profile".to_owned(),
                ));
            }
            intent.validate()?;
            if intent.transaction_id != self.transaction_id
                || intent.installation_plan_digest != self.plan_digest
                || intent.candidate_manifest_digest != self.manifest_digest
            {
                return Err(InstallationError::IdentityConflict);
            }
        }
        if let Some(stage) = &self.phase_b_agent_bridge_stage_prepared {
            let Some(intent) = self.phase_b_intent.as_ref() else {
                return Err(InstallationError::IdentityConflict);
            };
            if intent.agent_bridge_source.is_none() {
                return Err(InstallationError::IdentityConflict);
            }
            stage.validate_against_phase_b(intent, self)?;
        }
        if let Some(prepared) = &self.phase_b_prepared {
            if self.manifest.runtime_launch.profile != InstallationProfile::SystemService {
                return Err(InstallationError::ProfileViolation(
                    "Phase-B preparation requires the SystemService profile".to_owned(),
                ));
            }
            prepared.validate()?;
            if prepared.transaction_id != self.transaction_id
                || prepared.manifest_digest != self.manifest_digest
                || prepared.launch.generation != self.manifest.generation
                || prepared.launch.store_config_path != self.manifest.config_path
            {
                return Err(InstallationError::IdentityConflict);
            }
            let Some(intent) = self.phase_b_intent.as_ref() else {
                return Err(InstallationError::IdentityConflict);
            };
            if prepared.effect_id != intent.effect_id
                || prepared.credential_effect_id != intent.credential_effect_id
                || prepared.request_digest != intent.request_digest
                || prepared.credential_receipt_digest != intent.credential_receipt_digest
            {
                return Err(InstallationError::IdentityConflict);
            }
            match (
                &intent.agent_bridge_source,
                &self.phase_b_agent_bridge_stage_prepared,
                &prepared.agent_bridge,
            ) {
                (None, None, None) => {}
                (Some(_), Some(stage), Some(bridge)) if bridge.stage_prepared == *stage => {
                    bridge.validate_against_phase_b(intent, self)?;
                }
                _ => return Err(InstallationError::IdentityConflict),
            }
        }
        if let Some(receipt) = &self.phase_b_prepared_receipt {
            receipt.validate()?;
            let Some(prepared) = self.phase_b_prepared.as_ref() else {
                return Err(InstallationError::IdentityConflict);
            };
            if receipt.transaction_id != self.transaction_id
                || receipt.candidate_manifest_digest != self.manifest_digest
                || receipt.effect_id != prepared.effect_id
                || receipt.request_digest != prepared.request_digest
                || receipt.host_owner_epoch != prepared.host_owner_epoch
                || receipt.host_process_identity != prepared.host_process_identity
                || receipt.authority_descriptor_digest != prepared.authority_descriptor_digest
                || receipt.config_file_digest != prepared.config_file_digest
                || receipt.store_bootstrap_descriptor_digest
                    != prepared.store_bootstrap_descriptor_digest
                || receipt.eliotd_descriptor_digest != prepared.eliotd_descriptor_digest
                || receipt.provisioned_supervision_authority
                    != prepared.launch.provisioned_supervision_authority()?.clone()
                || receipt.agent_bridge != prepared.agent_bridge
            {
                return Err(InstallationError::IdentityConflict);
            }
            if self.phase_b_receipt.is_some() {
                return Err(InstallationError::IdentityConflict);
            }
        }
        if let Some(receipt) = &self.phase_b_receipt {
            if self.manifest.runtime_launch.profile != InstallationProfile::SystemService {
                return Err(InstallationError::ProfileViolation(
                    "Phase-B receipt requires the SystemService profile".to_owned(),
                ));
            }
            receipt.validate()?;
            if receipt.transaction_id != self.transaction_id
                || receipt.candidate_manifest_digest != self.manifest_digest
            {
                return Err(InstallationError::IdentityConflict);
            }
            let Some(intent) = self.phase_b_intent.as_ref() else {
                return Err(InstallationError::IdentityConflict);
            };
            if self.phase_b_prepared.is_none() || self.phase_b_agent_bridge_stage_prepared.is_some()
            {
                return Err(InstallationError::IdentityConflict);
            }
            if receipt.effect_id != intent.effect_id
                || receipt.request_digest != intent.request_digest
            {
                return Err(InstallationError::IdentityConflict);
            }
            let prepared_bridge = self
                .phase_b_prepared
                .as_ref()
                .and_then(|prepared| prepared.agent_bridge.as_ref());
            match (
                &intent.agent_bridge_source,
                prepared_bridge,
                receipt.agent_bridge.as_ref(),
            ) {
                (None, None, None) => {}
                (Some(_), Some(prepared_bridge), Some(receipt_bridge))
                    if receipt_bridge.matches_prepared_core(prepared_bridge) =>
                {
                    receipt_bridge.validate_against_phase_b(intent, self)?;
                }
                _ => return Err(InstallationError::IdentityConflict),
            }
        }
        if let PendingActivationState::RecoveryRequired { reason } = &self.state {
            text(reason, "pending_activation.state.reason")?;
        }
        Ok(())
    }
}
