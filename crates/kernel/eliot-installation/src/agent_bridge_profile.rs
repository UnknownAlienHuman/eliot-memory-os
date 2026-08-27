//! Installation-owned static admission profile for the external agent bridge.
//!
//! This module deliberately stops at the immutable Phase-B input.  It does not
//! admit a process, observe a live session, issue a request identity, or make
//! the profile available to Kernel.  Host materialization and Kernel transport
//! admission are separate consumers of this record.

use std::path::{Component, Path};

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ContractId, ContractVersion, ResourceGeneration, StateFence,
    canonical_json_bytes, sha256_hex,
};
use eliot_platform_windows::{
    FileIdentity, ProtectedPathLease, TrustedSourceBundle, TrustedSourceFileLease,
    windows_paths_equal,
};
use eliot_protocol::{AgentBridgeClientDeclaration, ProtocolRange, ProtocolVersion};
use eliot_runtime_contracts::{
    HealthVector, ModuleContract, ModuleGeneration, ModuleGenerationState,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{InstallationError, PlatformHandle, handle, sha256_handle, text};

/// Stable module identity bound by the installation profile.
pub const AGENT_BRIDGE_MODULE_ID: &str = "eliot-agent-bridge";
/// Stable wire identity of the installation profile record.
pub const AGENT_BRIDGE_INSTALLATION_PROFILE_WIRE_ID: &str =
    "eliot.kernel.installation.agent-bridge-profile";
/// Current wire version of the installation profile record.
pub const AGENT_BRIDGE_INSTALLATION_PROFILE_WIRE_VERSION: u16 = 1;
/// Maximum frame body admitted by this profile contract.
pub const AGENT_BRIDGE_MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;
/// Maximum number of entries admitted in one static policy set.
pub const AGENT_BRIDGE_MAX_POLICY_ENTRIES: usize = 64;
const PROFILE_ID_DOMAIN: &[u8] = b"eliot.installation.agent-bridge.profile-id.v1\0";
const AGENT_BRIDGE_RUNTIME_PROTOCOL: &str = "eliot.agent-bridge.v1";
const AGENT_BRIDGE_ACTIVATION_CAPABILITY: &str = "agent.bridge.activate";
const AGENT_BRIDGE_MODULE_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
const AGENT_BRIDGE_MODULE_GENERATION: u64 = 1;
const AGENT_BRIDGE_AUTHORITY_EPOCH: u64 = 1;

/// Maximum source bridge executable bytes observed by the installation seam.
pub const AGENT_BRIDGE_SOURCE_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// The stable interactive-session policy selected for the approved SID.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentBridgeCallerSessionPolicy {
    /// Require a live interactive session owned by the approved stable SID.
    AnyInteractiveSessionForApprovedSid,
}

/// Per-connection process evidence required by the static profile.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentBridgeProcessPolicy {
    /// Kernel must seal an exact OS-observed process for every connection.
    ExactProcessPerConnection,
}

/// Retained installation observation of the exact staged bridge executable.
///
/// This value is deliberately not serializable or cloneable. The protected
/// file lease remains alive while the profile is constructed, so raw path,
/// digest and file-identity claims cannot enter through the public factory.
pub struct RetainedAgentBridgeArtifact {
    path: PlatformHandle,
    sha256: PlatformHandle,
    identity: FileIdentity,
    _lease: ProtectedPathLease,
}

impl RetainedAgentBridgeArtifact {
    /// Retains and hashes the deterministic external-module artifact below the
    /// protected installation root.
    pub fn open(
        installation_root: &PlatformHandle,
        generation: ResourceGeneration,
    ) -> Result<Self, InstallationError> {
        let root = Path::new(installation_root.as_str());
        validate_absolute_root(root, "agent_bridge.installation_root")?;
        let expected = staged_executable_path(installation_root.as_str(), generation);
        let lease =
            ProtectedPathLease::open_existing_absolute(Path::new(&expected)).map_err(|error| {
                InstallationError::Platform(format!(
                    "agent_bridge.executable_path: protected file open failed: {error}"
                ))
            })?;
        lease
            .verify_stable_identity()
            .and_then(|()| lease.verify_path_identity())
            .map_err(|error| {
                InstallationError::Platform(format!(
                    "agent_bridge.executable_path: retained identity failed: {error}"
                ))
            })?;
        if !windows_paths_equal(lease.path(), Path::new(&expected)) {
            return Err(InstallationError::IdentityConflict);
        }
        let bytes = lease.read_bounded(512 * 1024 * 1024).map_err(|error| {
            InstallationError::Platform(format!(
                "agent_bridge.executable_path: retained read failed: {error}"
            ))
        })?;
        let sha256 = PlatformHandle::new(sha256_hex(&bytes))
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        Ok(Self {
            path: PlatformHandle::new(expected)
                .map_err(|error| InstallationError::Platform(error.to_string()))?,
            sha256,
            identity: lease.identity(),
            _lease: lease,
        })
    }
}

/// Retained, no-follow observation of an explicit source bridge executable.
///
/// The source path is opened as a regular file below a retained parent
/// contour.  The lease is intentionally neither serializable nor cloneable:
/// identity, size, and digest facts can only be obtained from this retained
/// OS object and are rechecked before a plan is emitted.
pub struct RetainedAgentBridgeSource {
    source_path: PlatformHandle,
    _source_bundle: TrustedSourceBundle,
    source_file: TrustedSourceFileLease,
}

impl std::fmt::Debug for RetainedAgentBridgeSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedAgentBridgeSource")
            .field("source_path", &self.source_path)
            .field("identity", &self.identity())
            .field("size", &self.size())
            .field("sha256", &self.sha256())
            .finish_non_exhaustive()
    }
}

impl RetainedAgentBridgeSource {
    /// Opens and retains one explicit absolute source executable.
    ///
    /// The parent contour and final file are opened without following reparse
    /// points.  The final path, regular-file kind, identity, size, and digest
    /// are measured by the platform observer before this value is returned.
    pub fn open(source_executable_path: &PlatformHandle) -> Result<Self, InstallationError> {
        let source_path = Path::new(source_executable_path.as_str());
        validate_absolute_source_executable(source_path)?;
        let parent = source_path
            .parent()
            .ok_or_else(|| InstallationError::InvalidField {
                field: "agent_bridge.source_executable_path".to_owned(),
                reason: "must have an absolute parent directory".to_owned(),
            })?;
        let file_name = source_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| InstallationError::InvalidField {
                field: "agent_bridge.source_executable_path".to_owned(),
                reason: "must have a UTF-8 regular-file name".to_owned(),
            })?;
        let source_bundle = TrustedSourceBundle::open(parent).map_err(|error| {
            InstallationError::Platform(format!(
                "agent_bridge.source_executable_path: source contour open failed: {error}"
            ))
        })?;
        let source_file = source_bundle.retain_file(file_name).map_err(|error| {
            InstallationError::Platform(format!(
                "agent_bridge.source_executable_path: source file observation failed: {error}"
            ))
        })?;
        if !windows_paths_equal(source_file.path(), source_path) {
            return Err(InstallationError::IdentityConflict);
        }
        let source_path = PlatformHandle::new(source_file.path().to_string_lossy().into_owned())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        Ok(Self {
            source_path,
            _source_bundle: source_bundle,
            source_file,
        })
    }

    /// Returns the canonical absolute source executable path.
    #[must_use]
    pub fn source_executable_path(&self) -> &PlatformHandle {
        &self.source_path
    }

    /// Returns the source file identity observed from the retained handle.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.source_file.identity()
    }

    /// Returns the source byte size observed from the retained handle.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.source_file.size()
    }

    /// Returns the lowercase source SHA-256 observed from the retained handle.
    #[must_use]
    pub fn sha256(&self) -> &str {
        self.source_file.sha256()
    }

    /// Re-reads and verifies the retained source through its no-follow handle.
    pub fn verify(&self) -> Result<(), InstallationError> {
        self.source_file
            .read_bounded(AGENT_BRIDGE_SOURCE_MAX_BYTES)
            .map(|_| ())
            .map_err(|error| {
                InstallationError::Platform(format!(
                    "agent_bridge.source_executable_path: retained source recheck failed: {error}"
                ))
            })
    }
}

/// Alias emphasizing that the retained source is an observation, not a path
/// claim supplied by a caller.
pub type RetainedAgentBridgeSourceObserver = RetainedAgentBridgeSource;

/// Installation-owned factory for source observations and materialization
/// plans.  No method accepts caller-supplied source identity, size, or hash.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AgentBridgeSourceMaterializationFactory;

impl AgentBridgeSourceMaterializationFactory {
    /// Returns the stateless source materialization factory.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Retains an explicit source executable for later plan construction.
    pub fn retain_source(
        source_executable_path: &PlatformHandle,
    ) -> Result<RetainedAgentBridgeSource, InstallationError> {
        RetainedAgentBridgeSource::open(source_executable_path)
    }

    /// Alias for [`Self::retain_source`].
    pub fn observe(
        source_executable_path: &PlatformHandle,
    ) -> Result<RetainedAgentBridgeSource, InstallationError> {
        Self::retain_source(source_executable_path)
    }

    /// Builds a source plan from a retained source observation.
    pub fn plan(
        source: &RetainedAgentBridgeSource,
        approved_user_sid: String,
        allowed_effects: Vec<String>,
        client_declaration: AgentBridgeClientDeclaration,
    ) -> Result<AgentBridgeSourceMaterializationPlan, InstallationError> {
        AgentBridgeSourceMaterializationPlan::from_retained_source(
            source,
            approved_user_sid,
            allowed_effects,
            client_declaration,
        )
    }

    /// Alias for [`Self::plan`].
    pub fn materialize_plan(
        source: &RetainedAgentBridgeSource,
        approved_user_sid: String,
        allowed_effects: Vec<String>,
        client_declaration: AgentBridgeClientDeclaration,
    ) -> Result<AgentBridgeSourceMaterializationPlan, InstallationError> {
        Self::plan(
            source,
            approved_user_sid,
            allowed_effects,
            client_declaration,
        )
    }
}

/// Builds the bridge source plan from the retained bridge artifact and the
/// independently observed Kernel executable.  The producer owns every static
/// bridge/module value; callers provide only the OS-resolved account SID, the
/// observed Kernel artifact digest, and the Host-approved protected snapshot
/// identity.  In particular, no CLI generation, fence, profile id, or
/// configuration-file digest is accepted as authority.
#[allow(
    clippy::too_many_lines,
    reason = "the bounded profile constructor keeps immutable bridge and Kernel bindings together"
)]
pub fn agent_bridge_source_plan_from_observed_kernel(
    source: &RetainedAgentBridgeSource,
    approved_user_sid: String,
    kernel_artifact_sha256: &str,
    protected_snapshot_digest: &str,
) -> Result<AgentBridgeSourceMaterializationPlan, InstallationError> {
    source.verify()?;
    if !is_lowercase_sha256(kernel_artifact_sha256) || kernel_artifact_sha256 == source.sha256() {
        return Err(InstallationError::IdentityConflict);
    }
    if !is_lowercase_sha256(protected_snapshot_digest) {
        return Err(InstallationError::InvalidField {
            field: "agent_bridge.protected_snapshot_digest".to_owned(),
            reason: "must be a lowercase SHA-256 digest".to_owned(),
        });
    }
    let module_id = ContractId::new(AGENT_BRIDGE_MODULE_ID).map_err(|error| {
        InstallationError::InvalidField {
            field: "agent_bridge.module_id".to_owned(),
            reason: error.to_string(),
        }
    })?;
    let artifact_id =
        ArtifactId::new(source.sha256()).map_err(|error| InstallationError::InvalidField {
            field: "agent_bridge.module_contract.artifact_id".to_owned(),
            reason: error.to_string(),
        })?;
    let module_generation =
        ResourceGeneration::new(AGENT_BRIDGE_MODULE_GENERATION).map_err(|error| {
            InstallationError::InvalidField {
                field: "agent_bridge.module_generation.generation".to_owned(),
                reason: error.to_string(),
            }
        })?;
    let authority_epoch = AuthorityEpoch::new(AGENT_BRIDGE_AUTHORITY_EPOCH).map_err(|error| {
        InstallationError::InvalidField {
            field: "agent_bridge.module_generation.state_fence.authority_epoch".to_owned(),
            reason: error.to_string(),
        }
    })?;
    let contract = ModuleContract {
        module_id: module_id.clone(),
        version: AGENT_BRIDGE_MODULE_VERSION,
        artifact_id: artifact_id.clone(),
        protocols: vec![AGENT_BRIDGE_RUNTIME_PROTOCOL.to_owned()],
        required_capabilities: vec![AGENT_BRIDGE_ACTIVATION_CAPABILITY.to_owned()],
        optional_capabilities: Vec::new(),
        advisory_capabilities: Vec::new(),
        state_owner: AGENT_BRIDGE_MODULE_ID.to_owned(),
        failure_domain: AGENT_BRIDGE_MODULE_ID.to_owned(),
        hot_replace: false,
    };
    let generation = ModuleGeneration {
        module_id,
        generation: module_generation,
        artifact_id,
        state: ModuleGenerationState::Ready,
        health: HealthVector::healthy(),
        state_fence: StateFence::new(authority_epoch, module_generation),
    };
    let kernel_snapshot = serde_json::json!({
        "service": "eliot-kernel",
        "protocol": "eliot.kernel.v1",
        "generation": AGENT_BRIDGE_AUTHORITY_EPOCH,
        "authority_epoch": AGENT_BRIDGE_AUTHORITY_EPOCH,
        "artifact_digest": kernel_artifact_sha256,
        "protected_snapshot_digest": protected_snapshot_digest,
    });
    let kernel_snapshot_sha256 =
        sha256_hex(&serde_json::to_vec(&kernel_snapshot).map_err(|error| {
            InstallationError::InvalidField {
                field: "agent_bridge.expected_kernel_config_snapshot_sha256".to_owned(),
                reason: error.to_string(),
            }
        })?);
    let declaration = AgentBridgeClientDeclaration {
        wire_id: eliot_protocol::AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION,
        module_id: AGENT_BRIDGE_MODULE_ID.to_owned(),
        profile_id: "pending".to_owned(),
        protocol_range: ProtocolRange {
            minimum: ProtocolVersion::CURRENT,
            maximum: ProtocolVersion::CURRENT,
        },
        module_contract: contract,
        module_generation: generation,
        capabilities: vec![AGENT_BRIDGE_ACTIVATION_CAPABILITY.to_owned()],
        privacy_classes: vec!["PUBLIC".to_owned()],
        max_frame: AGENT_BRIDGE_MAX_FRAME_BYTES,
        expected_kernel_sid: crate::LOCAL_SERVICE_SID.to_owned(),
        expected_kernel_session_id: 0,
        expected_kernel_principal_binding: format!("sid={};session=0", crate::LOCAL_SERVICE_SID),
        expected_kernel_authority_epoch: AuthorityEpoch::new(AGENT_BRIDGE_AUTHORITY_EPOCH)
            .map_err(|error| InstallationError::InvalidField {
                field: "agent_bridge.expected_kernel_authority_epoch".to_owned(),
                reason: error.to_string(),
            })?,
        expected_kernel_generation: ResourceGeneration::new(AGENT_BRIDGE_MODULE_GENERATION)
            .map_err(|error| InstallationError::InvalidField {
                field: "agent_bridge.expected_kernel_generation".to_owned(),
                reason: error.to_string(),
            })?,
        expected_kernel_artifact_sha256: kernel_artifact_sha256.to_owned(),
        expected_kernel_config_snapshot_sha256: kernel_snapshot_sha256,
        declaration_sha256: String::new(),
    };
    AgentBridgeSourceMaterializationPlan::from_retained_source(
        source,
        approved_user_sid,
        vec![AGENT_BRIDGE_ACTIVATION_CAPABILITY.to_owned()],
        declaration,
    )
}

/// Alias for callers that name the factory after its observer role.
pub type AgentBridgeSourceObserverFactory = AgentBridgeSourceMaterializationFactory;

/// Serializable, destination-free source materialization input for one
/// external agent bridge executable.
///
/// The source identity, size, and SHA-256 are copied only from a
/// [`RetainedAgentBridgeSource`].  Consumers must call [`Self::validate_against`]
/// with a retained observer before treating this record as current source
/// evidence.  This plan contains no destination path, write effect, PID,
/// session, request identity, candidate manifest, or runtime launch descriptor.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBridgeSourceMaterializationPlan {
    /// Explicit absolute source executable path.
    pub source_executable_path: PlatformHandle,
    /// Source file identity observed from the retained no-follow handle.
    pub source_executable_identity: FileIdentity,
    /// Lowercase SHA-256 observed from the source executable bytes.
    pub source_executable_sha256: PlatformHandle,
    /// Source executable byte size.
    pub source_executable_size: u64,
    /// Immutable bridge module contract.
    pub module_contract: ModuleContract,
    /// Immutable bridge module generation and internal registration fence.
    pub module_generation: ModuleGeneration,
    /// Canonical approved user SID for later profile construction.
    pub approved_user_sid: String,
    /// Effects allowed by the later static profile.
    pub allowed_effects: Vec<String>,
    /// Static bridge client declaration template.
    pub client_declaration: AgentBridgeClientDeclaration,
}

impl AgentBridgeSourceMaterializationPlan {
    /// Builds a source plan while deriving all source facts from the observer.
    pub fn from_retained_source(
        source: &RetainedAgentBridgeSource,
        approved_user_sid: String,
        allowed_effects: Vec<String>,
        mut client_declaration: AgentBridgeClientDeclaration,
    ) -> Result<Self, InstallationError> {
        source.verify()?;
        "pending".clone_into(&mut client_declaration.profile_id);
        client_declaration.declaration_sha256 =
            client_declaration.compute_digest().map_err(|error| {
                InstallationError::InvalidField {
                    field: "agent_bridge.client_declaration.declaration_sha256".to_owned(),
                    reason: error.to_string(),
                }
            })?;
        let plan = Self {
            source_executable_path: source.source_executable_path().clone(),
            source_executable_identity: source.identity(),
            source_executable_sha256: PlatformHandle::new(source.sha256().to_owned())
                .map_err(|error| InstallationError::Platform(error.to_string()))?,
            source_executable_size: source.size(),
            module_contract: client_declaration.module_contract.clone(),
            module_generation: client_declaration.module_generation.clone(),
            approved_user_sid,
            allowed_effects,
            client_declaration,
        };
        plan.validate_against(source)?;
        Ok(plan)
    }

    /// Validates the plan and rechecks its source facts against the retained
    /// no-follow source observer.
    #[allow(
        clippy::too_many_lines,
        reason = "one fail-closed boundary validates every source-plan domain together"
    )]
    pub fn validate_against(
        &self,
        source: &RetainedAgentBridgeSource,
    ) -> Result<(), InstallationError> {
        self.validate()?;
        source.verify()?;
        if self.source_executable_path != *source.source_executable_path()
            || self.source_executable_identity != source.identity()
            || self.source_executable_size != source.size()
            || self.source_executable_sha256.as_str() != source.sha256()
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    /// Validates the serializable plan's internal contract bindings.
    #[allow(
        clippy::too_many_lines,
        reason = "one fail-closed boundary validates every source-plan domain together"
    )]
    pub fn validate(&self) -> Result<(), InstallationError> {
        let source_path = Path::new(self.source_executable_path.as_str());
        validate_absolute_source_executable(source_path)?;
        sha256_handle(
            &self.source_executable_sha256,
            "agent_bridge.source_executable_sha256",
        )?;
        if self.source_executable_size == 0
            || self.source_executable_size > AGENT_BRIDGE_SOURCE_MAX_BYTES
        {
            return Err(InstallationError::InvalidField {
                field: "agent_bridge.source_executable_size".to_owned(),
                reason: "must be non-zero and within the 512 MiB source bound".to_owned(),
            });
        }
        if self.source_executable_identity.volume_serial_number == 0
            || self.source_executable_identity.file_index == 0
        {
            return Err(InstallationError::InvalidField {
                field: "agent_bridge.source_executable_identity".to_owned(),
                reason: "must identify a retained regular file".to_owned(),
            });
        }
        text(
            self.module_contract.module_id.as_str(),
            "agent_bridge.module_id",
        )?;
        self.module_contract
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "agent_bridge.module_contract".to_owned(),
                reason: error.to_string(),
            })?;
        unique_texts(
            &self.module_contract.protocols,
            "agent_bridge.module_contract.protocols",
        )?;
        unique_texts(
            &self.module_contract.required_capabilities,
            "agent_bridge.module_contract.required_capabilities",
        )?;
        if !self
            .module_contract
            .protocols
            .iter()
            .any(|protocol| protocol == AGENT_BRIDGE_RUNTIME_PROTOCOL)
            || !self
                .module_contract
                .required_capabilities
                .iter()
                .any(|capability| capability == AGENT_BRIDGE_ACTIVATION_CAPABILITY)
        {
            return Err(InstallationError::IdentityConflict);
        }
        self.module_generation
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "agent_bridge.module_generation".to_owned(),
                reason: error.to_string(),
            })?;
        if self.module_contract.module_id.as_str() != AGENT_BRIDGE_MODULE_ID
            || self.module_generation.module_id != self.module_contract.module_id
            || self.module_generation.artifact_id != self.module_contract.artifact_id
            || self.module_generation.state_fence.resource_generation
                != self.module_generation.generation
            || self.module_contract.artifact_id.as_str() != self.source_executable_sha256.as_str()
            || self.module_generation.artifact_id.as_str() != self.source_executable_sha256.as_str()
        {
            return Err(InstallationError::IdentityConflict);
        }
        if !is_canonical_sid(&self.approved_user_sid) {
            return Err(InstallationError::InvalidField {
                field: "agent_bridge.approved_user_sid".to_owned(),
                reason: "must be a canonical Windows SID".to_owned(),
            });
        }
        unique_texts(&self.allowed_effects, "agent_bridge.allowed_effects")?;
        unique_texts(
            &self.client_declaration.capabilities,
            "agent_bridge.client_declaration.capabilities",
        )?;
        unique_texts(
            &self.client_declaration.privacy_classes,
            "agent_bridge.client_declaration.privacy_classes",
        )?;
        if self.client_declaration.module_id != AGENT_BRIDGE_MODULE_ID
            || self.client_declaration.module_contract != self.module_contract
            || self.client_declaration.module_generation != self.module_generation
            || self.client_declaration.profile_id != "pending"
            || !self
                .module_contract
                .required_capabilities
                .iter()
                .all(|required| {
                    self.client_declaration
                        .capabilities
                        .iter()
                        .any(|allowed| allowed == required)
                })
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
                field: "agent_bridge.client_declaration.protocol_range".to_owned(),
                reason: "must overlap the current EBP protocol version".to_owned(),
            });
        }
        if self.client_declaration.expected_kernel_artifact_sha256
            == self.source_executable_sha256.as_str()
        {
            return Err(InstallationError::IdentityConflict);
        }
        self.client_declaration
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "agent_bridge.client_declaration".to_owned(),
                reason: error.to_string(),
            })?;
        Ok(())
    }
}

/// Deterministic protected record paths below the Host state root.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBridgeProtectedPaths {
    /// Protected immutable admission profile path.
    pub admission_profile_path: PlatformHandle,
    /// Protected immutable client declaration template path.
    pub client_declaration_path: PlatformHandle,
}

/// Installation-owned immutable admission input for one bridge generation.
///
/// The record carries no PID, process start time, session id, connection
/// challenge, request identity, semantic principal, task, `WorkScope`, plan or
/// mutable fence oracle.  Those values belong to the later Kernel connection
/// seal and eliotd semantic resolver boundaries.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBridgeInstallationProfile {
    /// Stable profile wire identity.
    pub wire_id: String,
    /// Profile wire version.
    pub wire_version: u16,
    /// Installation identity that selected this profile.
    pub installation_id: PlatformHandle,
    /// Explicit protected installation root containing the external module.
    pub installation_root: PlatformHandle,
    /// Explicit Host state root from which protected paths are derived.
    pub host_state_root: PlatformHandle,
    /// Stable profile identity derived from immutable profile inputs.
    pub profile_id: PlatformHandle,
    /// Exact external module identity.
    pub module_id: String,
    /// Immutable module contract.
    pub module_contract: ModuleContract,
    /// Immutable module generation and registration fence.
    pub module_generation: ModuleGeneration,
    /// Exact staged bridge executable path.
    pub executable_path: PlatformHandle,
    /// Lowercase SHA-256 of the staged bridge executable bytes.
    pub executable_sha256: PlatformHandle,
    /// File identity observed from the retained staged executable.
    pub executable_identity: FileIdentity,
    /// Canonical stable SID resolved by the installation adapter.
    pub approved_user_sid: String,
    /// Interactive-session policy for the approved SID.
    pub caller_session_policy: AgentBridgeCallerSessionPolicy,
    /// Required per-connection process sealing policy.
    pub process_policy: AgentBridgeProcessPolicy,
    /// Capabilities allowed by the static profile.
    pub allowed_capabilities: Vec<String>,
    /// Privacy classes allowed by the static profile.
    pub allowed_privacy_classes: Vec<String>,
    /// Effects allowed by the static profile.
    pub allowed_effects: Vec<String>,
    /// Maximum frame body accepted by the static profile.
    pub max_frame: u32,
    /// Protected module-specific record paths.
    pub protected_paths: AgentBridgeProtectedPaths,
    /// Static v2 client declaration template for this profile.
    pub client_declaration: AgentBridgeClientDeclaration,
    /// Lowercase SHA-256 over every profile field except this field.
    pub profile_sha256: PlatformHandle,
}

impl AgentBridgeInstallationProfile {
    /// Constructs a profile and derives its identity and protected paths.
    ///
    /// `client_declaration.profile_id` and its digest are regenerated from the
    /// resulting derived profile identity; caller-provided values for those
    /// fields are never treated as authority.  The executable path must equal
    /// the deterministic staging location below `host_state_root`.
    pub fn from_retained_artifact(
        installation_id: PlatformHandle,
        installation_root: PlatformHandle,
        host_state_root: PlatformHandle,
        staged_artifact: &RetainedAgentBridgeArtifact,
        approved_user_sid: String,
        allowed_effects: Vec<String>,
        client_declaration: AgentBridgeClientDeclaration,
    ) -> Result<Self, InstallationError> {
        Self::from_observed_artifact(
            installation_id,
            installation_root,
            host_state_root,
            staged_artifact.path.clone(),
            staged_artifact.sha256.clone(),
            staged_artifact.identity,
            approved_user_sid,
            allowed_effects,
            client_declaration,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the profile constructor keeps every installation-owned identity input explicit"
    )]
    fn from_observed_artifact(
        installation_id: PlatformHandle,
        installation_root: PlatformHandle,
        host_state_root: PlatformHandle,
        staged_executable_path: PlatformHandle,
        staged_executable_sha256: PlatformHandle,
        staged_executable_identity: FileIdentity,
        approved_user_sid: String,
        allowed_effects: Vec<String>,
        mut client_declaration: AgentBridgeClientDeclaration,
    ) -> Result<Self, InstallationError> {
        let protected_paths = derive_agent_bridge_protected_paths(&host_state_root)?;
        "pending".clone_into(&mut client_declaration.profile_id);
        client_declaration.declaration_sha256 =
            client_declaration.compute_digest().map_err(|error| {
                InstallationError::InvalidField {
                    field: "client_declaration.declaration_sha256".to_owned(),
                    reason: error.to_string(),
                }
            })?;
        let mut profile = Self {
            wire_id: AGENT_BRIDGE_INSTALLATION_PROFILE_WIRE_ID.to_owned(),
            wire_version: AGENT_BRIDGE_INSTALLATION_PROFILE_WIRE_VERSION,
            installation_id,
            installation_root,
            host_state_root,
            profile_id: PlatformHandle::new("pending")
                .map_err(|error| InstallationError::Platform(error.to_string()))?,
            module_id: AGENT_BRIDGE_MODULE_ID.to_owned(),
            module_contract: client_declaration.module_contract.clone(),
            module_generation: client_declaration.module_generation.clone(),
            executable_path: staged_executable_path,
            executable_sha256: staged_executable_sha256,
            executable_identity: staged_executable_identity,
            approved_user_sid,
            caller_session_policy:
                AgentBridgeCallerSessionPolicy::AnyInteractiveSessionForApprovedSid,
            process_policy: AgentBridgeProcessPolicy::ExactProcessPerConnection,
            allowed_capabilities: client_declaration.capabilities.clone(),
            allowed_privacy_classes: client_declaration.privacy_classes.clone(),
            allowed_effects,
            max_frame: client_declaration.max_frame,
            protected_paths,
            client_declaration,
            profile_sha256: PlatformHandle::new("pending")
                .map_err(|error| InstallationError::Platform(error.to_string()))?,
        };
        profile.validate_without_derived_digests()?;
        let profile_id = profile.derive_profile_id()?;
        profile.profile_id = profile_id;
        profile.client_declaration.profile_id = profile.profile_id.as_str().to_owned();
        profile.client_declaration.declaration_sha256 = profile
            .client_declaration
            .compute_digest()
            .map_err(|error| InstallationError::InvalidField {
                field: "client_declaration".to_owned(),
                reason: error.to_string(),
            })?;
        profile.profile_sha256 =
            profile
                .compute_digest()
                .map_err(|error| InstallationError::InvalidField {
                    field: "profile_sha256".to_owned(),
                    reason: error.to_string(),
                })?;
        profile.validate()?;
        Ok(profile)
    }

    /// Returns canonical bytes covered by `profile_sha256`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, InstallationError> {
        let mut unsigned =
            serde_json::to_value(self).map_err(|error| InstallationError::InvalidField {
                field: "profile_sha256".to_owned(),
                reason: error.to_string(),
            })?;
        unsigned
            .as_object_mut()
            .ok_or_else(|| InstallationError::InvalidField {
                field: "profile_sha256".to_owned(),
                reason: "profile projection is not an object".to_owned(),
            })?
            .remove("profile_sha256")
            .ok_or_else(|| InstallationError::InvalidField {
                field: "profile_sha256".to_owned(),
                reason: "profile digest field is missing".to_owned(),
            })?;
        canonical_json_bytes(&unsigned).map_err(|error| InstallationError::InvalidField {
            field: "profile_sha256".to_owned(),
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
        sha256_handle(&self.profile_id, "agent_bridge.profile_id")?;
        sha256_handle(&self.profile_sha256, "agent_bridge.profile_sha256")?;
        let expected_id = self.derive_profile_id()?;
        if self.profile_id != expected_id {
            return Err(InstallationError::IdentityConflict);
        }
        if self.compute_digest()? != self.profile_sha256 {
            return Err(InstallationError::IdentityConflict);
        }
        if self.client_declaration.profile_id != self.profile_id.as_str() {
            return Err(InstallationError::IdentityConflict);
        }
        let expected_declaration_digest =
            self.client_declaration.compute_digest().map_err(|error| {
                InstallationError::InvalidField {
                    field: "client_declaration.declaration_sha256".to_owned(),
                    reason: error.to_string(),
                }
            })?;
        if self.client_declaration.declaration_sha256 != expected_declaration_digest {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one fail-closed boundary validates every immutable profile domain together"
    )]
    fn validate_without_derived_digests(&self) -> Result<(), InstallationError> {
        if self.wire_id != AGENT_BRIDGE_INSTALLATION_PROFILE_WIRE_ID
            || self.wire_version != AGENT_BRIDGE_INSTALLATION_PROFILE_WIRE_VERSION
        {
            return Err(InstallationError::InvalidField {
                field: "agent_bridge.wire_version".to_owned(),
                reason: "unsupported installation profile wire identity/version".to_owned(),
            });
        }
        handle(&self.installation_id, "agent_bridge.installation_id")?;
        text(&self.module_id, "agent_bridge.module_id")?;
        if self.module_id != AGENT_BRIDGE_MODULE_ID {
            return Err(InstallationError::IdentityConflict);
        }
        self.module_contract
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "agent_bridge.module_contract".to_owned(),
                reason: error.to_string(),
            })?;
        unique_texts(
            &self.module_contract.protocols,
            "agent_bridge.module_contract.protocols",
        )?;
        unique_texts(
            &self.module_contract.required_capabilities,
            "agent_bridge.module_contract.required_capabilities",
        )?;
        if !self
            .module_contract
            .protocols
            .iter()
            .any(|protocol| protocol == AGENT_BRIDGE_RUNTIME_PROTOCOL)
            || !self
                .module_contract
                .required_capabilities
                .iter()
                .any(|capability| capability == AGENT_BRIDGE_ACTIVATION_CAPABILITY)
        {
            return Err(InstallationError::IdentityConflict);
        }
        self.module_generation
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "agent_bridge.module_generation".to_owned(),
                reason: error.to_string(),
            })?;
        if self.module_contract.module_id.as_str() != self.module_id
            || self.module_generation.module_id != self.module_contract.module_id
            || self.module_generation.artifact_id != self.module_contract.artifact_id
            || self.module_generation.state_fence.resource_generation
                != self.module_generation.generation
            || self.module_contract.artifact_id.as_str() != self.executable_sha256.as_str()
        {
            return Err(InstallationError::IdentityConflict);
        }
        sha256_handle(&self.executable_sha256, "agent_bridge.executable_sha256")?;
        if self.executable_identity.volume_serial_number == 0
            || self.executable_identity.file_index == 0
        {
            return Err(InstallationError::InvalidField {
                field: "agent_bridge.executable_identity".to_owned(),
                reason: "must identify a retained non-absent file object".to_owned(),
            });
        }
        if !is_canonical_sid(&self.approved_user_sid) {
            return Err(InstallationError::InvalidField {
                field: "agent_bridge.approved_user_sid".to_owned(),
                reason: "must be a canonical Windows SID".to_owned(),
            });
        }
        let installation_root = Path::new(self.installation_root.as_str());
        let host_state_root = Path::new(self.host_state_root.as_str());
        validate_absolute_root(installation_root, "agent_bridge.installation_root")?;
        validate_absolute_root(host_state_root, "agent_bridge.host_state_root")?;
        if !host_state_root.starts_with(installation_root) || host_state_root == installation_root {
            return Err(InstallationError::InvalidField {
                field: "agent_bridge.host_state_root".to_owned(),
                reason: "must be a strict child of the protected installation root".to_owned(),
            });
        }
        let expected_paths = derive_agent_bridge_protected_paths(&self.host_state_root)?;
        if self.protected_paths != expected_paths {
            return Err(InstallationError::IdentityConflict);
        }
        let expected_executable = staged_executable_path(
            self.installation_root.as_str(),
            self.module_generation.generation,
        );
        let executable = Path::new(self.executable_path.as_str());
        if !executable.is_absolute()
            || executable
                .components()
                .any(|component| matches!(component, Component::ParentDir))
            || self.executable_path.as_str() != expected_executable
        {
            return Err(InstallationError::InvalidField {
                field: "agent_bridge.executable_path".to_owned(),
                reason: "must be the exact protected staging path".to_owned(),
            });
        }
        unique_texts(
            &self.allowed_capabilities,
            "agent_bridge.allowed_capabilities",
        )?;
        unique_texts(
            &self.allowed_privacy_classes,
            "agent_bridge.allowed_privacy_classes",
        )?;
        unique_texts(&self.allowed_effects, "agent_bridge.allowed_effects")?;
        if !self
            .module_contract
            .required_capabilities
            .iter()
            .all(|required| {
                self.allowed_capabilities
                    .iter()
                    .any(|allowed| allowed == required)
            })
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
                field: "agent_bridge.client_declaration.protocol_range".to_owned(),
                reason: "must overlap the current EBP protocol version".to_owned(),
            });
        }
        if self.max_frame == 0 || self.max_frame > AGENT_BRIDGE_MAX_FRAME_BYTES {
            return Err(InstallationError::InvalidField {
                field: "agent_bridge.max_frame".to_owned(),
                reason: "must be within the admitted frame ceiling".to_owned(),
            });
        }
        if self.allowed_capabilities != self.client_declaration.capabilities
            || self.allowed_privacy_classes != self.client_declaration.privacy_classes
            || self.max_frame != self.client_declaration.max_frame
            || self.client_declaration.module_id != self.module_id
            || self.client_declaration.module_contract != self.module_contract
            || self.client_declaration.module_generation != self.module_generation
        {
            return Err(InstallationError::IdentityConflict);
        }
        // The declaration's expected Kernel generation/epoch and the bridge
        // module generation/fence are deliberately separate authority domains.
        // The later Phase-B producer compares the Kernel expectation with the
        // exact candidate; this static record must never alias the two domains.
        self.client_declaration
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "agent_bridge.client_declaration".to_owned(),
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
                field: "agent_bridge.profile_id".to_owned(),
                reason: error.to_string(),
            }
        })?);
        PlatformHandle::new(sha256_hex(&bytes))
            .map_err(|error| InstallationError::Platform(error.to_string()))
    }
}

/// Derives the two protected profile record paths below an explicit Host root.
pub fn derive_agent_bridge_protected_paths(
    host_state_root: &PlatformHandle,
) -> Result<AgentBridgeProtectedPaths, InstallationError> {
    let root = Path::new(host_state_root.as_str());
    validate_absolute_root(root, "agent_bridge.host_state_root")?;
    let directory = root.join("agent-bridge");
    let admission = directory.join("admission-profile-v1.json");
    let declaration = directory.join("client-declaration-v2.json");
    if !admission.starts_with(root) || !declaration.starts_with(root) {
        return Err(InstallationError::InvalidField {
            field: "agent_bridge.host_state_root".to_owned(),
            reason: "derived profile paths escaped the Host state root".to_owned(),
        });
    }
    Ok(AgentBridgeProtectedPaths {
        admission_profile_path: path_handle(&admission, "admission_profile_path")?,
        client_declaration_path: path_handle(&declaration, "client_declaration_path")?,
    })
}

fn staged_executable_path(root: &str, generation: ResourceGeneration) -> String {
    Path::new(root)
        .join("external-modules")
        .join(AGENT_BRIDGE_MODULE_ID)
        .join(generation.value().to_string())
        .join("eliot-agent-bridge.exe")
        .to_string_lossy()
        .into_owned()
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

fn validate_absolute_source_executable(path: &Path) -> Result<(), InstallationError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        || path.file_name().is_none()
        || path.parent().is_none()
    {
        return Err(InstallationError::InvalidField {
            field: "agent_bridge.source_executable_path".to_owned(),
            reason: "must be an explicit absolute normalized executable path".to_owned(),
        });
    }
    Ok(())
}

fn path_handle(path: &Path, field: &str) -> Result<PlatformHandle, InstallationError> {
    PlatformHandle::new(path.to_string_lossy().into_owned()).map_err(|error| {
        InstallationError::InvalidField {
            field: format!("agent_bridge.{field}"),
            reason: error.to_string(),
        }
    })
}

fn unique_texts(values: &[String], field: &str) -> Result<(), InstallationError> {
    if values.len() > AGENT_BRIDGE_MAX_POLICY_ENTRIES {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "exceeds the bounded policy-set limit".to_owned(),
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        text(value, field)?;
        if !seen.insert(value) {
            return Err(InstallationError::Duplicate {
                kind: field.to_owned(),
                identity: value.clone(),
            });
        }
    }
    Ok(())
}

fn is_canonical_sid(value: &str) -> bool {
    let Some(tail) = value.strip_prefix("S-1-") else {
        return false;
    };
    let parts: Vec<_> = tail.split('-').collect();
    if !(1..=16).contains(&parts.len()) || parts.iter().any(|part| part.is_empty()) {
        return false;
    }
    let canonical_decimal = |part: &str| {
        part.bytes().all(|byte| byte.is_ascii_digit()) && (part == "0" || !part.starts_with('0'))
    };
    if !parts.iter().all(|part| canonical_decimal(part)) {
        return false;
    }
    let Ok(authority) = parts[0].parse::<u64>() else {
        return false;
    };
    authority <= 0x0000_FFFF_FFFF_FFFF && parts[1..].iter().all(|part| part.parse::<u32>().is_ok())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "bounded deterministic contract fixtures"
)]
mod tests {
    use super::*;
    use eliot_contracts::{ArtifactId, AuthorityEpoch, ContractId, ContractVersion, StateFence};
    use eliot_protocol::{
        AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION, ProtocolRange, ProtocolVersion,
    };
    use eliot_runtime_contracts::{HealthVector, ModuleGenerationState};
    use tempfile::tempdir;

    fn declaration() -> AgentBridgeClientDeclaration {
        let fence = StateFence::new(
            AuthorityEpoch::new(3).unwrap(),
            ResourceGeneration::new(7).unwrap(),
        );
        let artifact = ArtifactId::new("a".repeat(64)).unwrap();
        let module = ContractId::new(AGENT_BRIDGE_MODULE_ID).unwrap();
        let contract = ModuleContract {
            module_id: module.clone(),
            version: ContractVersion::new(1, 0, 0),
            artifact_id: artifact.clone(),
            protocols: vec![AGENT_BRIDGE_RUNTIME_PROTOCOL.to_owned()],
            required_capabilities: vec!["agent.bridge.activate".to_owned()],
            optional_capabilities: Vec::new(),
            advisory_capabilities: Vec::new(),
            state_owner: "eliot-agent-bridge".to_owned(),
            failure_domain: "agent-bridge".to_owned(),
            hot_replace: false,
        };
        let generation = ModuleGeneration {
            module_id: module,
            generation: ResourceGeneration::new(7).unwrap(),
            artifact_id: artifact,
            state: ModuleGenerationState::Ready,
            health: HealthVector::healthy(),
            state_fence: fence,
        };
        AgentBridgeClientDeclaration {
            wire_id: eliot_protocol::AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_ID.to_owned(),
            wire_version: AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION,
            module_id: AGENT_BRIDGE_MODULE_ID.to_owned(),
            profile_id: "caller-value".to_owned(),
            protocol_range: ProtocolRange {
                minimum: ProtocolVersion { major: 1, minor: 0 },
                maximum: ProtocolVersion { major: 1, minor: 0 },
            },
            module_contract: contract,
            module_generation: generation,
            capabilities: vec!["agent.bridge.activate".to_owned()],
            privacy_classes: vec!["PUBLIC".to_owned()],
            max_frame: AGENT_BRIDGE_MAX_FRAME_BYTES,
            expected_kernel_sid: "S-1-5-18".to_owned(),
            expected_kernel_session_id: 0,
            expected_kernel_principal_binding: "kernel:eliot-agent-bridge".to_owned(),
            expected_kernel_authority_epoch: AuthorityEpoch::new(3).unwrap(),
            expected_kernel_generation: ResourceGeneration::new(7).unwrap(),
            expected_kernel_artifact_sha256: "b".repeat(64),
            expected_kernel_config_snapshot_sha256: "c".repeat(64),
            declaration_sha256: String::new(),
        }
    }

    fn profile() -> AgentBridgeInstallationProfile {
        profile_from_declaration(declaration()).unwrap()
    }

    fn profile_from_declaration(
        declaration: AgentBridgeClientDeclaration,
    ) -> Result<AgentBridgeInstallationProfile, InstallationError> {
        let root = tempdir().unwrap();
        let installation_root = PlatformHandle::new(root.path().to_string_lossy()).unwrap();
        let host_state_root =
            PlatformHandle::new(root.path().join("host").to_string_lossy()).unwrap();
        let executable = PlatformHandle::new(staged_executable_path(
            root.path().to_str().unwrap(),
            ResourceGeneration::new(7).unwrap(),
        ))
        .unwrap();
        AgentBridgeInstallationProfile::from_observed_artifact(
            PlatformHandle::new("installation-1").unwrap(),
            installation_root,
            host_state_root,
            executable,
            PlatformHandle::new("a".repeat(64)).unwrap(),
            FileIdentity {
                volume_serial_number: 1,
                file_index: 2,
            },
            "S-1-5-21-1-2-3-1001".to_owned(),
            vec!["activate".to_owned()],
            declaration,
        )
    }

    fn source_plan() -> (
        tempfile::TempDir,
        RetainedAgentBridgeSource,
        AgentBridgeSourceMaterializationPlan,
    ) {
        let root = tempdir().unwrap();
        let source_path = root.path().join("eliot-agent-bridge.exe");
        std::fs::write(&source_path, b"bridge-source-bytes").unwrap();
        let source_hash = sha256_hex(b"bridge-source-bytes");
        let mut client = declaration();
        client.module_contract.artifact_id = ArtifactId::new(source_hash.clone()).unwrap();
        client.module_generation.artifact_id = client.module_contract.artifact_id.clone();
        let source_handle = PlatformHandle::new(source_path.to_string_lossy()).unwrap();
        let retained = RetainedAgentBridgeSource::open(&source_handle).unwrap();
        let plan = AgentBridgeSourceMaterializationPlan::from_retained_source(
            &retained,
            "S-1-5-21-1-2-3-1001".to_owned(),
            vec!["activate".to_owned()],
            client,
        )
        .unwrap();
        (root, retained, plan)
    }

    #[test]
    fn derives_stable_profile_and_protected_paths() {
        let value = profile();
        assert_eq!(value.validate(), Ok(()));
        assert_eq!(value.profile_id.as_str().len(), 64);
        assert!(
            value
                .protected_paths
                .admission_profile_path
                .as_str()
                .ends_with("agent-bridge/admission-profile-v1.json")
                || value
                    .protected_paths
                    .admission_profile_path
                    .as_str()
                    .ends_with("agent-bridge\\admission-profile-v1.json")
        );
        assert!(
            value
                .protected_paths
                .client_declaration_path
                .as_str()
                .contains("client-declaration-v2.json")
        );
    }

    #[test]
    fn rejects_substitution_and_noncanonical_sid() {
        let mut value = profile();
        value.executable_sha256 = PlatformHandle::new("e".repeat(64)).unwrap();
        assert!(value.validate().is_err());
        assert!(!is_canonical_sid("S-1-5-21-01"));
        assert!(!is_canonical_sid("S-1-5-21--1"));
        assert!(!is_canonical_sid("S-1-5-21-4294967296"));
        assert!(!is_canonical_sid("S-1-18446744073709551616"));
    }

    #[test]
    fn rejects_path_escape_and_unknown_json_fields() {
        let root = PlatformHandle::new("relative-root").unwrap();
        assert!(derive_agent_bridge_protected_paths(&root).is_err());
        let encoded = serde_json::to_value(profile()).unwrap();
        let mut object = encoded.as_object().unwrap().clone();
        object.insert("unexpected".to_owned(), serde_json::Value::Null);
        assert!(
            serde_json::from_value::<AgentBridgeInstallationProfile>(serde_json::Value::Object(
                object
            ))
            .is_err()
        );
    }

    #[test]
    fn digest_excludes_only_itself_and_roots_policy_sets_remain_bounded() {
        let value = profile();
        let canonical = value.canonical_unsigned_bytes().unwrap();
        let mut digest_substitution = value.clone();
        digest_substitution.profile_sha256 = PlatformHandle::new("f".repeat(64)).unwrap();
        assert_eq!(
            digest_substitution.canonical_unsigned_bytes().unwrap(),
            canonical
        );
        assert!(digest_substitution.validate().is_err());

        let mut foreign_root = value.clone();
        foreign_root.host_state_root =
            PlatformHandle::new(std::env::temp_dir().join("foreign-host").to_string_lossy())
                .unwrap();
        foreign_root.protected_paths =
            derive_agent_bridge_protected_paths(&foreign_root.host_state_root).unwrap();
        assert!(foreign_root.validate().is_err());

        let mut oversized = value;
        oversized.allowed_effects = (0..=AGENT_BRIDGE_MAX_POLICY_ENTRIES)
            .map(|index| format!("effect-{index}"))
            .collect();
        assert!(oversized.validate().is_err());
    }

    #[test]
    fn rejects_noncanonical_protocol_missing_required_capability_and_disjoint_range() {
        let mut wrong_protocol = declaration();
        wrong_protocol.module_contract.protocols = vec!["foreign.protocol.v1".to_owned()];
        assert!(profile_from_declaration(wrong_protocol).is_err());

        let mut missing_capability = declaration();
        missing_capability
            .module_contract
            .required_capabilities
            .clear();
        assert!(profile_from_declaration(missing_capability).is_err());

        let mut disallowed_required_capability = declaration();
        disallowed_required_capability
            .module_contract
            .required_capabilities
            .push("agent.bridge.admin".to_owned());
        assert!(profile_from_declaration(disallowed_required_capability).is_err());

        let mut disjoint_range = declaration();
        disjoint_range.protocol_range = ProtocolRange {
            minimum: ProtocolVersion {
                major: ProtocolVersion::CURRENT.major,
                minor: ProtocolVersion::CURRENT.minor.saturating_add(1),
            },
            maximum: ProtocolVersion {
                major: ProtocolVersion::CURRENT.major,
                minor: ProtocolVersion::CURRENT.minor.saturating_add(1),
            },
        };
        assert!(profile_from_declaration(disjoint_range).is_err());
    }

    #[test]
    fn source_plan_accepts_same_file_and_rechecks_retained_facts() {
        let (_root, retained, plan) = source_plan();
        assert_eq!(plan.validate_against(&retained), Ok(()));
        assert_eq!(
            plan.source_executable_size,
            b"bridge-source-bytes".len() as u64
        );
        assert_eq!(plan.source_executable_sha256.as_str(), retained.sha256());
        assert_eq!(plan.source_executable_identity, retained.identity());
    }

    #[test]
    fn source_plan_rejects_substitution_path_sid_protocol_and_capability() {
        let (_root, retained, plan) = source_plan();

        let mut substituted_hash = plan.clone();
        substituted_hash.source_executable_sha256 = PlatformHandle::new("f".repeat(64)).unwrap();
        assert!(substituted_hash.validate_against(&retained).is_err());

        let mut substituted_path = plan.clone();
        substituted_path.source_executable_path =
            PlatformHandle::new("C:\\foreign\\eliot-agent-bridge.exe").unwrap();
        assert!(substituted_path.validate_against(&retained).is_err());

        let mut bad_sid = plan.clone();
        bad_sid.approved_user_sid = "S-1-5-21-01".to_owned();
        assert!(bad_sid.validate().is_err());

        let mut bad_protocol = plan.clone();
        bad_protocol.module_contract.protocols = vec!["foreign.protocol.v1".to_owned()];
        assert!(bad_protocol.validate().is_err());

        let mut substituted_profile = plan.clone();
        substituted_profile.client_declaration.profile_id = "substituted-profile".to_owned();
        substituted_profile.client_declaration.declaration_sha256 = substituted_profile
            .client_declaration
            .compute_digest()
            .unwrap();
        assert!(substituted_profile.validate().is_err());

        let mut bad_capability = plan;
        bad_capability.client_declaration.capabilities.clear();
        assert!(bad_capability.validate().is_err());
    }

    #[test]
    fn source_plan_rejects_unknown_json_fields() {
        let (_root, _retained, plan) = source_plan();
        let mut object = serde_json::to_value(plan)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        object.insert("unexpected".to_owned(), serde_json::Value::Null);
        assert!(
            serde_json::from_value::<AgentBridgeSourceMaterializationPlan>(
                serde_json::Value::Object(object)
            )
            .is_err()
        );
    }
}
