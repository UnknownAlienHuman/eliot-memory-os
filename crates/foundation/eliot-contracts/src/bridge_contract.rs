//! I6.5 bridge contract: the versioned declaration of one external-process
//! or protocol bridge's mechanical boundary.
//!
//! A bridge translates, isolates and observes. It MUST NOT contain project
//! semantics that belong in Governor/Dreamer. This module owns the neutral
//! `BridgeContract` value: one versioned declaration per actual bridge,
//! carrying every I6.5 field and the exact boundary where the bridge stops
//! translating/isolating/observing and the Governor/Dreamer owner resumes.
//!
//! The contract is bound to the admitted artifact/config/route generation by
//! the consuming bridge crate, never to a mutable README or a self-reported
//! version alone. Unknown required metadata remains a qualification gap:
//! `validate` refuses an incomplete declaration instead of filling it in.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContractError, validate_text};

/// Current wire revision of the bridge contract declaration.
pub const BRIDGE_CONTRACT_REVISION: u64 = 1;

/// Maximum number of capabilities, data classes, side effects, or failure
/// translations carried by one bridge contract.
pub const MAX_BRIDGE_ENTRIES: usize = 64;

/// Maximum length of one bridge contract text field.
pub const MAX_BRIDGE_TEXT_LEN: usize = 1024;

/// Stable bridge identity (for example `eliot-agent-bridge`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
#[schemars(transparent)]
pub struct BridgeId(String);

impl BridgeId {
    /// Constructs a validated bridge identity.
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        validate_text(&value, "bridge_contract.bridge_id")?;
        if value.len() > MAX_BRIDGE_TEXT_LEN {
            return Err(ContractError::TooLong {
                field: "bridge_contract.bridge_id",
                maximum_bytes: MAX_BRIDGE_TEXT_LEN,
            });
        }
        Ok(Self(value))
    }

    /// Returns the canonical identity text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes this identity and returns its text.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for BridgeId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::str::FromStr for BridgeId {
    type Err = ContractError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for BridgeId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for BridgeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Upstream project name and license.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpstreamProject {
    /// Exact upstream project name.
    pub name: String,
    /// Upstream license identifier (SPDX when applicable).
    pub license: String,
}

impl UpstreamProject {
    /// Validates the upstream project declaration.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.name, "bridge_contract.upstream_project.name")?;
        validate_text(&self.license, "bridge_contract.upstream_project.license")?;
        Ok(())
    }
}

/// Exact upstream version and artifact identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpstreamVersion {
    /// Exact upstream version string.
    pub version: String,
    /// Artifact identity (package id, digest, or path) the version binds to.
    pub artifact: String,
}

impl UpstreamVersion {
    /// Validates the upstream version declaration.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.version, "bridge_contract.upstream_version.version")?;
        validate_text(&self.artifact, "bridge_contract.upstream_version.artifact")?;
        Ok(())
    }
}

/// One ELIOT capability the bridge serves and its protocol mapping.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeCapability {
    /// ELIOT capability served (for example `agent.activation`).
    pub capability: String,
    /// How the upstream protocol maps onto the ELIOT capability.
    pub protocol_mapping: String,
}

impl BridgeCapability {
    /// Validates one capability entry.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.capability, "bridge_contract.capability.capability")?;
        validate_text(
            &self.protocol_mapping,
            "bridge_contract.capability.protocol_mapping",
        )?;
        Ok(())
    }
}

/// One data class crossing the bridge.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
#[schemars(transparent)]
pub struct DataClass(String);

impl DataClass {
    /// Constructs a validated data class.
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        validate_text(&value, "bridge_contract.data_class")?;
        Ok(Self(value))
    }

    /// Returns the canonical data class text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DataClass {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::str::FromStr for DataClass {
    type Err = ContractError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for DataClass {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DataClass {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Credentials boundary declaration: who owns credentials and what crosses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialsBoundary {
    /// Owner of the credentials (for example `user-broker`).
    pub owner: String,
    /// True when only opaque references cross the bridge, never raw secrets.
    pub refs_only: bool,
    /// Description of the exact boundary.
    pub boundary: String,
}

impl CredentialsBoundary {
    /// Validates the credentials boundary declaration.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.owner, "bridge_contract.credentials_boundary.owner")?;
        validate_text(
            &self.boundary,
            "bridge_contract.credentials_boundary.boundary",
        )?;
        Ok(())
    }
}

/// One side effect the bridge may trigger and the authority that gates it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SideEffect {
    /// The side effect (for example `process.start`).
    pub effect: String,
    /// Authority that gates the effect (for example `kernel.capability-token`).
    pub authority: String,
}

impl SideEffect {
    /// Validates one side effect entry.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.effect, "bridge_contract.side_effect.effect")?;
        validate_text(&self.authority, "bridge_contract.side_effect.authority")?;
        Ok(())
    }
}

/// Timeout and cancellation semantics of the bridge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TimeoutsAndCancellation {
    /// Request timeout in milliseconds, when the bridge declares one.
    pub request_timeout_ms: Option<u64>,
    /// Cancellation semantics (for example `executor.cancel(operation-id)`).
    pub cancellation: String,
}

impl TimeoutsAndCancellation {
    /// Validates the timeout and cancellation declaration.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(
            &self.cancellation,
            "bridge_contract.timeouts_and_cancellation.cancellation",
        )?;
        Ok(())
    }
}

/// Health probe declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HealthProbe {
    /// How health is probed (for example `read-only status query`).
    pub probe: String,
    /// True when the probe is read-only and performs no mutation.
    pub read_only: bool,
}

impl HealthProbe {
    /// Validates the health probe declaration.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.probe, "bridge_contract.health_probe.probe")?;
        Ok(())
    }
}

/// One failure translation rule: upstream failure to ELIOT failure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureTranslation {
    /// Upstream failure identity.
    pub upstream_failure: String,
    /// ELIOT failure identity it translates to.
    pub eliot_failure: String,
    /// How the translation preserves the boundary (no task decision granted).
    pub boundary: String,
}

impl FailureTranslation {
    /// Validates one failure translation entry.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(
            &self.upstream_failure,
            "bridge_contract.failure_translation.upstream_failure",
        )?;
        validate_text(
            &self.eliot_failure,
            "bridge_contract.failure_translation.eliot_failure",
        )?;
        validate_text(
            &self.boundary,
            "bridge_contract.failure_translation.boundary",
        )?;
        Ok(())
    }
}

/// Process executor profile: which executor and contour the bridge uses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessExecutorProfile {
    /// The process executor (for example `P-03 ProcessExecutor`).
    pub executor: String,
    /// The execution contour (for example `single-take launch binding`).
    pub contour: String,
    /// True when the bridge uses a single-take process binding.
    pub single_take: bool,
}

impl ProcessExecutorProfile {
    /// Validates the process executor profile.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(
            &self.executor,
            "bridge_contract.process_executor_profile.executor",
        )?;
        validate_text(
            &self.contour,
            "bridge_contract.process_executor_profile.contour",
        )?;
        Ok(())
    }
}

/// Suite revision for the independent contract suite or fixture corpus.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SuiteRevision {
    /// Suite identity.
    pub suite: String,
    /// Exact suite revision.
    pub revision: String,
}

impl SuiteRevision {
    /// Validates one suite revision.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.suite, "bridge_contract.suite.suite")?;
        validate_text(&self.revision, "bridge_contract.suite.revision")?;
        Ok(())
    }
}

/// Update method: how a bridge generation is staged, cut over, and rolled back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateMethod {
    /// The update method (for example `staged-generation-cutover`).
    pub method: String,
    /// Compatibility check performed before route exposure.
    pub compatibility: String,
}

impl UpdateMethod {
    /// Validates the update method declaration.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.method, "bridge_contract.update_method.method")?;
        validate_text(
            &self.compatibility,
            "bridge_contract.update_method.compatibility",
        )?;
        Ok(())
    }
}

/// Export and removal path declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportRemovalPath {
    /// How observations and evidence are exported.
    pub export: String,
    /// How the bridge is removed (fence, drain, revoke, remove artifacts).
    pub removal: String,
}

impl ExportRemovalPath {
    /// Validates the export/removal path declaration.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.export, "bridge_contract.export_removal_path.export")?;
        validate_text(&self.removal, "bridge_contract.export_removal_path.removal")?;
        Ok(())
    }
}

/// The versioned I6.5 bridge contract declaration.
///
/// One declaration per actual bridge. The bridge translates, isolates and
/// observes; task meaning, policy decisions and promotion remain with their
/// existing Governor/Dreamer owners. The `owner_resume` field records the
/// exact boundary where the bridge stops and the owner resumes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeContract {
    /// Contract revision. Must equal [`BRIDGE_CONTRACT_REVISION`].
    pub contract_revision: u64,
    /// Stable bridge identity.
    pub bridge_id: BridgeId,
    /// Upstream project name and license.
    pub upstream_project_and_license: UpstreamProject,
    /// Exact upstream version and artifact.
    pub upstream_version: UpstreamVersion,
    /// ELIOT capabilities the bridge serves and their protocol mapping.
    pub eliot_capabilities: Vec<BridgeCapability>,
    /// Data classes crossing the bridge.
    pub data_classes: Vec<DataClass>,
    /// Credentials boundary declaration.
    pub credentials_boundary: CredentialsBoundary,
    /// Side effects the bridge may trigger and their gating authority.
    pub side_effects: Vec<SideEffect>,
    /// Timeout and cancellation semantics.
    pub timeouts_and_cancellation: TimeoutsAndCancellation,
    /// Health probe declaration.
    pub health_probe: HealthProbe,
    /// Failure translation rules.
    pub failure_translation: Vec<FailureTranslation>,
    /// Process executor profile.
    pub process_executor_profile: ProcessExecutorProfile,
    /// Independent contract suite revision.
    pub independent_contract_suite: SuiteRevision,
    /// Fixture and golden corpus revision.
    pub fixture_and_golden_corpus: SuiteRevision,
    /// Update method.
    pub update_method: UpdateMethod,
    /// Export and removal path.
    pub export_removal_path: ExportRemovalPath,
    /// The exact boundary where the bridge stops translating/isolating/
    /// observing and the Governor/Dreamer owner resumes.
    pub owner_resume: String,
}

impl BridgeContract {
    /// Validates the complete bridge contract declaration.
    ///
    /// Every I6.5 field must be present and non-empty. Unknown required
    /// metadata remains a qualification gap: validation refuses an incomplete
    /// declaration instead of filling it in.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_revision != BRIDGE_CONTRACT_REVISION {
            return Err(ContractError::VersionOutOfRange);
        }
        self.upstream_project_and_license.validate()?;
        self.upstream_version.validate()?;
        if self.eliot_capabilities.is_empty() {
            return Err(ContractError::Blank {
                field: "bridge_contract.eliot_capabilities",
            });
        }
        if self.eliot_capabilities.len() > MAX_BRIDGE_ENTRIES {
            return Err(ContractError::TooLong {
                field: "bridge_contract.eliot_capabilities",
                maximum_bytes: MAX_BRIDGE_ENTRIES,
            });
        }
        for capability in &self.eliot_capabilities {
            capability.validate()?;
        }
        if self.data_classes.is_empty() {
            return Err(ContractError::Blank {
                field: "bridge_contract.data_classes",
            });
        }
        if self.data_classes.len() > MAX_BRIDGE_ENTRIES {
            return Err(ContractError::TooLong {
                field: "bridge_contract.data_classes",
                maximum_bytes: MAX_BRIDGE_ENTRIES,
            });
        }
        self.credentials_boundary.validate()?;
        if self.side_effects.is_empty() {
            return Err(ContractError::Blank {
                field: "bridge_contract.side_effects",
            });
        }
        if self.side_effects.len() > MAX_BRIDGE_ENTRIES {
            return Err(ContractError::TooLong {
                field: "bridge_contract.side_effects",
                maximum_bytes: MAX_BRIDGE_ENTRIES,
            });
        }
        for side_effect in &self.side_effects {
            side_effect.validate()?;
        }
        self.timeouts_and_cancellation.validate()?;
        self.health_probe.validate()?;
        if self.failure_translation.is_empty() {
            return Err(ContractError::Blank {
                field: "bridge_contract.failure_translation",
            });
        }
        if self.failure_translation.len() > MAX_BRIDGE_ENTRIES {
            return Err(ContractError::TooLong {
                field: "bridge_contract.failure_translation",
                maximum_bytes: MAX_BRIDGE_ENTRIES,
            });
        }
        for translation in &self.failure_translation {
            translation.validate()?;
        }
        self.process_executor_profile.validate()?;
        self.independent_contract_suite.validate()?;
        self.fixture_and_golden_corpus.validate()?;
        self.update_method.validate()?;
        self.export_removal_path.validate()?;
        validate_text(&self.owner_resume, "bridge_contract.owner_resume")?;
        Ok(())
    }
}
