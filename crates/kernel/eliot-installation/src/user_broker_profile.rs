//! Installation-owned static front-door profile for the interactive User Broker.
//!
//! This module is the counterpart of `agent_bridge_profile` for the
//! `eliot-user-broker` module. It stops at the immutable Phase-B input: it does
//! not admit a process, observe a live session, mint a registration or session
//! token, or make the profile available to Kernel. Host Phase B materialization
//! and Kernel transport admission are separate consumers of this record.
//!
//! Why this record exists: the broker's front door presents a
//! [`eliot_protocol::ClientHello`], and the serving Kernel admits an exact
//! operation-selector set from it. I7.3 fixes the declaration's contents
//! ("capabilities"), and the broker's protected launch binding states that
//! "Kernel connection/challenge material stays owned by the Kernel client
//! declaration". That declaration must therefore be an installed, immutable,
//! digest-bound record with exactly one producer. Before this module the only
//! such record in the tree was the agent bridge's, whose
//! `validate()` is bound to the `eliot-agent-bridge` module identity, so no
//! broker-side declaration could be produced at all.

use std::path::{Component, Path};

use eliot_contracts::{
    ArtifactId, ContractId, ContractVersion, canonical_json_bytes, sha256_hex,
};
use eliot_protocol::{
    ProtocolRange, ProtocolVersion, USER_BROKER_CLIENT_DECLARATION_WIRE_ID,
    USER_BROKER_CLIENT_DECLARATION_WIRE_VERSION, USER_BROKER_FRONT_DOOR_OPERATIONS,
    USER_BROKER_MODULE_ID, USER_BROKER_RUNTIME_PROTOCOL, UserBrokerClientDeclaration,
};
use eliot_runtime_contracts::{
    HealthVector, ModuleContract, ModuleGeneration, ModuleGenerationState,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    InstallationError, PlatformHandle, RuntimeLaunchDescriptor, approved_path, handle,
    sha256_handle, text,
};

/// Stable wire identity of the User Broker installation profile record.
pub const USER_BROKER_INSTALLATION_PROFILE_WIRE_ID: &str =
    "eliot.kernel.installation.user-broker-profile";
/// Current wire version of the User Broker installation profile record.
pub const USER_BROKER_INSTALLATION_PROFILE_WIRE_VERSION: u16 = 1;
/// Maximum frame body admitted by this profile contract.
pub const USER_BROKER_MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;
const PROFILE_ID_DOMAIN: &[u8] = b"eliot.installation.user-broker.profile-id.v1\0";
const USER_BROKER_MODULE_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
const USER_BROKER_REGISTRATION_OPERATION: &str = "eliot.user-broker.register";

/// Deterministic protected record path below the Host state root.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserBrokerProtectedPaths {
    /// Protected immutable client declaration template path.
    pub client_declaration_path: PlatformHandle,
}

/// Derives the protected broker declaration record path below an explicit Host
/// root.
pub fn derive_user_broker_protected_paths(
    host_state_root: &PlatformHandle,
) -> Result<UserBrokerProtectedPaths, InstallationError> {
    let root = Path::new(host_state_root.as_str());
    validate_absolute_root(root, "user_broker.host_state_root")?;
    let declaration = root.join("user-broker").join("client-declaration-v1.json");
    if !declaration.starts_with(root) {
        return Err(InstallationError::InvalidField {
            field: "user_broker.host_state_root".to_owned(),
            reason: "derived profile paths escaped the Host state root".to_owned(),
        });
    }
    Ok(UserBrokerProtectedPaths {
        client_declaration_path: PlatformHandle::new(declaration.to_string_lossy().into_owned())
            .map_err(|error| InstallationError::Platform(error.to_string()))?,
    })
}

/// Installation-owned immutable front-door input for one User Broker
/// generation.
///
/// The record carries no PID, process start time, session id, connection
/// challenge, request identity, semantic principal, task, `WorkScope`, plan,
/// clock, or mutable fence oracle. The broker's registration, heartbeat, launch
/// authorization, fencing, and per-connection evidence belong to the later
/// Kernel session boundary; nothing here can mint or revive them. A restart
/// re-derives this record from a different approved launch contour, so a new
/// installation never revives the previous generation's front door.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserBrokerInstallationProfile {
    /// Stable profile wire identity.
    pub wire_id: String,
    /// Profile wire version.
    pub wire_version: u16,
    /// Installation identity that selected this profile.
    pub installation_id: PlatformHandle,
    /// Explicit protected installation root containing the staged broker.
    pub installation_root: PlatformHandle,
    /// Explicit Host state root from which the protected path is derived.
    pub host_state_root: PlatformHandle,
    /// Stable profile identity derived from immutable profile inputs.
    pub profile_id: PlatformHandle,
    /// Exact module identity.
    pub module_id: String,
    /// Immutable module contract.
    pub module_contract: ModuleContract,
    /// Immutable module generation and registration fence.
    pub module_generation: ModuleGeneration,
    /// Exact staged per-user broker executable path.
    pub broker_executable_path: PlatformHandle,
    /// Lowercase SHA-256 of the staged per-user broker executable bytes.
    pub broker_artifact_sha256: PlatformHandle,
    /// Protected module-specific record paths.
    pub protected_paths: UserBrokerProtectedPaths,
    /// Static client declaration template for this profile.
    pub client_declaration: UserBrokerClientDeclaration,
    /// Lowercase SHA-256 over every profile field except this field.
    pub profile_sha256: PlatformHandle,
}

impl UserBrokerInstallationProfile {
    /// Builds the profile for one already approved launch contour.
    ///
    /// This is the record's only producer. Every broker fact is copied from the
    /// installation-owned [`RuntimeLaunchDescriptor`] that Phase B has already
    /// re-proved against the protected root; no caller supplies a path, digest,
    /// capability, frame bound, or identity. The module contract, generation,
    /// and exact operation-selector set are owned here, so a broker front door
    /// cannot be installed with an expanded or narrowed capability set.
    pub fn from_approved_launch(
        launch: &RuntimeLaunchDescriptor,
    ) -> Result<Self, InstallationError> {
        let module_id = ContractId::new(USER_BROKER_MODULE_ID).map_err(|error| {
            InstallationError::InvalidField {
                field: "user_broker.module_id".to_owned(),
                reason: error.to_string(),
            }
        })?;
        let artifact_id = ArtifactId::new(launch.user_broker_artifact_digest.as_str()).map_err(
            |error| InstallationError::InvalidField {
                field: "user_broker.module_contract.artifact_id".to_owned(),
                reason: error.to_string(),
            },
        )?;
        let operations: Vec<String> = USER_BROKER_FRONT_DOOR_OPERATIONS
            .iter()
            .map(|operation| (*operation).to_owned())
            .collect();
        let contract = ModuleContract {
            module_id: module_id.clone(),
            version: USER_BROKER_MODULE_VERSION,
            artifact_id: artifact_id.clone(),
            protocols: vec![USER_BROKER_RUNTIME_PROTOCOL.to_owned()],
            capabilities: Vec::new(),
            required_capabilities: operations.clone(),
            optional_capabilities: Vec::new(),
            advisory_capabilities: Vec::new(),
            state_owner: USER_BROKER_MODULE_ID.to_owned(),
            failure_domain: USER_BROKER_MODULE_ID.to_owned(),
            owner: USER_BROKER_MODULE_ID.to_owned(),
            hot_replace: false,
            startup_after: vec![USER_BROKER_REGISTRATION_OPERATION.to_owned()],
            drain_before: vec![USER_BROKER_REGISTRATION_OPERATION.to_owned()],
            invalidation_triggers: Vec::new(),
            supervision_plan: "one_for_one".to_owned(),
            child_restart: "transient".to_owned(),
            restart_intensity: "3/10m".to_owned(),
            resource_profile: "interactive-user".to_owned(),
            privacy_classes: vec!["PUBLIC".to_owned()],
            permissions: Vec::new(),
            health_contract: "health/user-broker-v1".to_owned(),
            checkpoint_contract: "checkpoint/user-broker-v1".to_owned(),
            compatibility_state: "rebuildable".to_owned(),
            independent_test_profile: "module/user-broker".to_owned(),
            contract_fixture_set: format!(
                "{USER_BROKER_RUNTIME_PROTOCOL}/{USER_BROKER_REGISTRATION_OPERATION}"
            ),
            affected_test_tags: vec!["user-broker".to_owned(), "process".to_owned()],
            architecture: Vec::new(),
            telemetry: "telemetry/user-broker-v1".to_owned(),
            removal_boundary: "user-broker".to_owned(),
        };
        let state_fence = launch.authority_state_fence.clone();
        let generation = ModuleGeneration {
            module_id,
            generation: state_fence.resource_generation,
            artifact_id,
            state: ModuleGenerationState::Ready,
            health: HealthVector::healthy(),
            state_fence,
        };
        let declaration = UserBrokerClientDeclaration {
            wire_id: USER_BROKER_CLIENT_DECLARATION_WIRE_ID.to_owned(),
            wire_version: USER_BROKER_CLIENT_DECLARATION_WIRE_VERSION,
            module_id: USER_BROKER_MODULE_ID.to_owned(),
            profile_id: "pending".to_owned(),
            protocol_range: ProtocolRange {
                minimum: ProtocolVersion::CURRENT,
                maximum: ProtocolVersion::CURRENT,
            },
            module_contract: contract,
            module_generation: generation,
            capabilities: operations,
            privacy_classes: vec!["PUBLIC".to_owned()],
            max_frame: USER_BROKER_MAX_FRAME_BYTES,
            declaration_sha256: String::new(),
        };
        let host_state_root = launch.runtime_state_roots.host_state_root.clone();
        let mut profile = Self {
            wire_id: USER_BROKER_INSTALLATION_PROFILE_WIRE_ID.to_owned(),
            wire_version: USER_BROKER_INSTALLATION_PROFILE_WIRE_VERSION,
            installation_id: launch.installation_epoch.installation.clone(),
            installation_root: launch.runtime_state_roots.installation_root.clone(),
            host_state_root: host_state_root.clone(),
            profile_id: PlatformHandle::new("pending")
                .map_err(|error| InstallationError::Platform(error.to_string()))?,
            module_id: USER_BROKER_MODULE_ID.to_owned(),
            module_contract: declaration.module_contract.clone(),
            module_generation: declaration.module_generation.clone(),
            broker_executable_path: launch.user_broker_executable_path.clone(),
            broker_artifact_sha256: launch.user_broker_artifact_digest.clone(),
            protected_paths: derive_user_broker_protected_paths(&host_state_root)?,
            profile_sha256: PlatformHandle::new("pending")
                .map_err(|error| InstallationError::Platform(error.to_string()))?,
            client_declaration: declaration
                .with_computed_digest()
                .map_err(|error| InstallationError::InvalidField {
                    field: "user_broker.client_declaration".to_owned(),
                    reason: error.to_string(),
                })?,
        };
        profile.validate_without_derived_digests()?;
        let profile_id = profile.derive_profile_id()?;
        profile.profile_id = profile_id;
        profile.client_declaration.profile_id = profile.profile_id.as_str().to_owned();
        profile.client_declaration = profile
            .client_declaration
            .clone()
            .with_computed_digest()
            .map_err(|error| InstallationError::InvalidField {
                field: "user_broker.client_declaration".to_owned(),
                reason: error.to_string(),
            })?;
        profile.profile_sha256 =
            profile
                .compute_digest()
                .map_err(|error| InstallationError::InvalidField {
                    field: "user_broker.profile_sha256".to_owned(),
                    reason: error.to_string(),
                })?;
        profile.validate()?;
        Ok(profile)
    }

    /// Returns canonical bytes covered by `profile_sha256`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, InstallationError> {
        let mut unsigned =
            serde_json::to_value(self).map_err(|error| InstallationError::InvalidField {
                field: "user_broker.profile_sha256".to_owned(),
                reason: error.to_string(),
            })?;
        unsigned
            .as_object_mut()
            .ok_or_else(|| InstallationError::InvalidField {
                field: "user_broker.profile_sha256".to_owned(),
                reason: "profile projection is not an object".to_owned(),
            })?
            .remove("profile_sha256")
            .ok_or_else(|| InstallationError::InvalidField {
                field: "user_broker.profile_sha256".to_owned(),
                reason: "profile digest field is missing".to_owned(),
            })?;
        canonical_json_bytes(&unsigned).map_err(|error| InstallationError::InvalidField {
            field: "user_broker.profile_sha256".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Computes the lowercase SHA-256 profile digest.
    pub fn compute_digest(&self) -> Result<PlatformHandle, InstallationError> {
        PlatformHandle::new(sha256_hex(&self.canonical_unsigned_bytes()?))
            .map_err(|error| InstallationError::Platform(error.to_string()))
    }

    /// Validates the complete immutable profile and all derived bindings.
    pub fn validate(&self) -> Result<(), InstallationError> {
        self.validate_without_derived_digests()?;
        sha256_handle(&self.profile_id, "user_broker.profile_id")?;
        sha256_handle(&self.profile_sha256, "user_broker.profile_sha256")?;
        if self.profile_id != self.derive_profile_id()? {
            return Err(InstallationError::IdentityConflict);
        }
        if self.compute_digest()? != self.profile_sha256 {
            return Err(InstallationError::IdentityConflict);
        }
        if self.client_declaration.profile_id != self.profile_id.as_str() {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one fail-closed boundary validates every immutable profile domain together"
    )]
    fn validate_without_derived_digests(&self) -> Result<(), InstallationError> {
        if self.wire_id != USER_BROKER_INSTALLATION_PROFILE_WIRE_ID
            || self.wire_version != USER_BROKER_INSTALLATION_PROFILE_WIRE_VERSION
        {
            return Err(InstallationError::InvalidField {
                field: "user_broker.wire_version".to_owned(),
                reason: "unsupported installation profile wire identity/version".to_owned(),
            });
        }
        handle(&self.installation_id, "user_broker.installation_id")?;
        text(&self.module_id, "user_broker.module_id")?;
        if self.module_id != USER_BROKER_MODULE_ID {
            return Err(InstallationError::IdentityConflict);
        }
        self.module_contract
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "user_broker.module_contract".to_owned(),
                reason: error.to_string(),
            })?;
        self.module_generation
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "user_broker.module_generation".to_owned(),
                reason: error.to_string(),
            })?;
        if self.module_contract.module_id.as_str() != self.module_id
            || self.module_generation.module_id != self.module_contract.module_id
            || self.module_generation.artifact_id != self.module_contract.artifact_id
            || self.module_generation.generation
                != self.module_generation.state_fence.resource_generation
            || self.module_contract.artifact_id.as_str() != self.broker_artifact_sha256.as_str()
        {
            return Err(InstallationError::IdentityConflict);
        }
        sha256_handle(
            &self.broker_artifact_sha256,
            "user_broker.broker_artifact_sha256",
        )?;
        if self.module_generation.generation.value() == 0 {
            return Err(InstallationError::InvalidField {
                field: "user_broker.module_generation.generation".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        let installation_root = Path::new(self.installation_root.as_str());
        let host_state_root = Path::new(self.host_state_root.as_str());
        validate_absolute_root(installation_root, "user_broker.installation_root")?;
        validate_absolute_root(host_state_root, "user_broker.host_state_root")?;
        if !host_state_root.starts_with(installation_root) || host_state_root == installation_root {
            return Err(InstallationError::InvalidField {
                field: "user_broker.host_state_root".to_owned(),
                reason: "must be a strict child of the protected installation root".to_owned(),
            });
        }
        if self.protected_paths != derive_user_broker_protected_paths(&self.host_state_root)? {
            return Err(InstallationError::IdentityConflict);
        }
        approved_path(
            &self.broker_executable_path,
            "user_broker.broker_executable_path",
        )?;
        if !Path::new(self.broker_executable_path.as_str())
            .starts_with(Path::new(self.installation_root.as_str()))
        {
            return Err(InstallationError::InvalidField {
                field: "user_broker.broker_executable_path".to_owned(),
                reason: "must be a staged broker path below the protected installation root"
                    .to_owned(),
            });
        }
        // The declared capability set is installation-owned and complete: it
        // must equal the exact front-door operation set, never a superset or a
        // subset of it.
        let expected_operations: Vec<String> = USER_BROKER_FRONT_DOOR_OPERATIONS
            .iter()
            .map(|operation| (*operation).to_owned())
            .collect();
        if self.module_contract.required_capabilities != expected_operations
            || self.client_declaration.capabilities != expected_operations
        {
            return Err(InstallationError::IdentityConflict);
        }
        let current_protocol = ProtocolRange {
            minimum: ProtocolVersion::CURRENT,
            maximum: ProtocolVersion::CURRENT,
        };
        if self
            .client_declaration
            .protocol_range
            .select(current_protocol)
            .is_err()
        {
            return Err(InstallationError::InvalidField {
                field: "user_broker.client_declaration.protocol_range".to_owned(),
                reason: "must overlap the current EBP protocol version".to_owned(),
            });
        }
        if self.client_declaration.module_id != self.module_id
            || self.client_declaration.module_contract != self.module_contract
            || self.client_declaration.module_generation != self.module_generation
            || self.client_declaration.max_frame != USER_BROKER_MAX_FRAME_BYTES
        {
            return Err(InstallationError::IdentityConflict);
        }
        // The declaration validates the recorded `declaration_sha256` against
        // its own canonical bytes; it is never re-derived here as a substitute.
        self.client_declaration
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "user_broker.client_declaration".to_owned(),
                reason: error.to_string(),
            })?;
        Ok(())
    }

    fn derive_profile_id(&self) -> Result<PlatformHandle, InstallationError> {
        let mut seed = self.clone();
        seed.profile_id = PlatformHandle::new("pending")
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        seed.profile_sha256 = PlatformHandle::new("pending")
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        seed.client_declaration.profile_id.clear();
        seed.client_declaration.declaration_sha256.clear();
        let mut bytes = PROFILE_ID_DOMAIN.to_vec();
        bytes.extend_from_slice(&canonical_json_bytes(&seed).map_err(|error| {
            InstallationError::InvalidField {
                field: "user_broker.profile_id".to_owned(),
                reason: error.to_string(),
            }
        })?);
        PlatformHandle::new(sha256_hex(&bytes))
            .map_err(|error| InstallationError::Platform(error.to_string()))
    }
}

fn validate_absolute_root(root: &Path, field: &str) -> Result<(), InstallationError> {
    if !root.is_absolute()
        || root
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must be an absolute normalized protected root".to_owned(),
        });
    }
    Ok(())
}
