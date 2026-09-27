//! Validated external bridge manifests and route-bound admission observations.
//!
//! These values describe an admission contract; constructing one grants no
//! authority and does not prove that the recorded probes actually ran.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Route, validate_text};

/// External adapter family. Claude's local sidecar and managed service are
/// intentionally distinct adapter identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BridgeType {
    CodexAppServer,
    OpenCode,
    ClaudeLocalAgentSdk,
    ClaudeManagedAgents,
    Acp,
}

/// Exact upstream/runtime identity declared by an adapter manifest.
/// `runtime_artifact_sha256` identifies the profile's pinned runtime artifact;
/// for Codex App Server that artifact is the executable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeRuntimeIdentity {
    pub upstream: String,
    pub version: String,
    pub runtime_artifact_sha256: String,
    pub fingerprint: String,
}

impl BridgeRuntimeIdentity {
    fn validate(&self) -> Result<(), BridgeAdmissionError> {
        validate_text(&self.upstream, "runtime.upstream")?;
        validate_text(&self.version, "runtime.version")?;
        validate_sha256(
            &self.runtime_artifact_sha256,
            "runtime.runtime_artifact_sha256",
        )?;
        validate_text(&self.fingerprint, "runtime.fingerprint")?;
        Ok(())
    }
}

/// Recorded license information. This is descriptive evidence, not a legal
/// compatibility decision or an authority grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeLicenseRecord {
    pub license: String,
    pub source_ref: String,
    pub reviewed_revision: String,
}

/// Declared transport and security boundary for an adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BridgeTransport {
    StdioNdjson,
    AuthenticatedLoopbackHttpSse,
    AuthenticatedHttp,
    SupervisedSidecarNdjson,
    Acp,
}

/// Endpoint boundary declared by a transport contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BridgeEndpointScope {
    LocalProcess,
    Loopback,
    RemoteService,
    AdapterRuntime,
}

/// Explicit transport properties; profile validation enforces its required
/// authentication and endpoint boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeTransportContract {
    pub transport: BridgeTransport,
    pub authenticated: bool,
    pub endpoint_scope: BridgeEndpointScope,
}

/// Positive declared byte bound for one direction of an adapter contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeSchemaBound {
    pub schema_ref: String,
    pub max_bytes: u64,
}

/// Scope, effect, and credential policy recorded for an external adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgePolicy {
    pub scope: String,
    pub effects: Vec<String>,
    pub credentials: String,
}

/// Typed failure categories that an adapter must translate for ordinary
/// governed reconciliation.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BridgeFailureKind {
    Crash,
    Interruption,
    UnknownOutcome,
    StaleSession,
    UnsupportedCapability,
    CleanupFailure,
}

/// Typed bridge state consumed by reconciliation; none of these states means
/// success or authorizes a retry on another route.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BridgeReconciliationState {
    Failed,
    Interrupted,
    UnknownOutcome,
    StaleSession,
    UnsupportedCapability,
    CleanupFailure,
}

/// Complete failure translation mapping. Every field is required on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeFailureTranslation {
    pub crash: BridgeReconciliationState,
    pub interruption: BridgeReconciliationState,
    pub unknown_outcome: BridgeReconciliationState,
    pub stale_session: BridgeReconciliationState,
    pub unsupported_capability: BridgeReconciliationState,
    pub cleanup_failure: BridgeReconciliationState,
}

impl BridgeFailureTranslation {
    fn validate(self) -> Result<(), BridgeAdmissionError> {
        let expected = [
            (self.crash, BridgeReconciliationState::Failed),
            (self.interruption, BridgeReconciliationState::Interrupted),
            (
                self.unknown_outcome,
                BridgeReconciliationState::UnknownOutcome,
            ),
            (self.stale_session, BridgeReconciliationState::StaleSession),
            (
                self.unsupported_capability,
                BridgeReconciliationState::UnsupportedCapability,
            ),
            (
                self.cleanup_failure,
                BridgeReconciliationState::CleanupFailure,
            ),
        ];
        if expected.iter().any(|(actual, required)| actual != required) {
            return Err(BridgeAdmissionError::InvalidFailureTranslation);
        }
        Ok(())
    }

    fn state_for(self, kind: BridgeFailureKind) -> BridgeReconciliationState {
        match kind {
            BridgeFailureKind::Crash => self.crash,
            BridgeFailureKind::Interruption => self.interruption,
            BridgeFailureKind::UnknownOutcome => self.unknown_outcome,
            BridgeFailureKind::StaleSession => self.stale_session,
            BridgeFailureKind::UnsupportedCapability => self.unsupported_capability,
            BridgeFailureKind::CleanupFailure => self.cleanup_failure,
        }
    }
}

/// Export and rebuild contract for adapter-owned state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeStateContract {
    pub exported_state_ref: String,
    pub rebuild_procedure_ref: String,
}

/// Replace and remove target for an adapter integration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeLifecycleTarget {
    pub replacement_target: String,
    pub removal_target: String,
}

/// Independently gated experimental operation. Opt-in requires exact
/// descriptor, negotiation, negative-proof, and rollback references.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeExperimentalOperation {
    pub operation: String,
    pub enabled_by_default: bool,
    pub descriptor_ref: String,
    pub negotiation_ref: String,
    pub negative_proof_ref: String,
    pub rollback_ref: String,
}

/// Typed capability limitation observed for one provisional route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeCapabilityLimitation {
    pub capability: String,
    pub kind: BridgeCapabilityLimitKind,
    pub detail: String,
}

/// Why a capability is unavailable to the exact admitted route.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BridgeCapabilityLimitKind {
    Unsupported,
    Unprobed,
    ExperimentalDisabled,
}

impl BridgeExperimentalOperation {
    fn validate(&self) -> Result<(), BridgeAdmissionError> {
        validate_text(&self.operation, "experimental.operation")?;
        for (value, field) in [
            (&self.descriptor_ref, "experimental.descriptor_ref"),
            (&self.negotiation_ref, "experimental.negotiation_ref"),
            (&self.negative_proof_ref, "experimental.negative_proof_ref"),
            (&self.rollback_ref, "experimental.rollback_ref"),
        ] {
            validate_text(value, field)?;
        }
        if self.enabled_by_default {
            return Err(BridgeAdmissionError::ExperimentalEnabledByDefault);
        }
        Ok(())
    }
}

/// Codex App Server's stable generated schema is tied to an exact executable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodexAppServerProfile {
    pub stable_only: bool,
    pub generated_schema_sha256: String,
    pub schema_bound_executable_sha256: String,
    pub experimental_operations: Vec<BridgeExperimentalOperation>,
}

/// `OpenCode` uses public session/event APIs for reconciliation. Internal
/// storage inspection can only be represented as explicitly degraded,
/// read-only forensics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeProfile {
    pub normal_reconciliation: OpenCodeReconciliationContract,
    pub internal_storage_forensics: Option<OpenCodeForensics>,
}

/// Documented `OpenCode` public session and event API used for reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OpenCodeReconciliationContract {
    PublicSessionEventApi,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeForensics {
    pub read_only: bool,
    pub degraded: bool,
    pub evidence_ref: String,
}

/// Local Agent SDK sidecar profile, distinct from managed agents.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaudeLocalAgentSdkProfile {
    pub sidecar_contract_ref: String,
}

/// Remote Claude Managed Agents profile, with its own lifecycle contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaudeManagedAgentsProfile {
    pub managed_contract_ref: String,
}

/// ACP v1 is the production baseline; v2 operations remain independently
/// rollbackable experiments and default to disabled.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AcpProfile {
    pub production_baseline: String,
    pub exact_runtime_probe_ref: String,
    pub v2_draft_operations: Vec<BridgeExperimentalOperation>,
}

/// Adapter-specific contract. The manifest's `bridge_type` must match this
/// profile variant exactly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "profile",
    content = "contract",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum BridgeProfileContract {
    CodexAppServer(CodexAppServerProfile),
    OpenCode(OpenCodeProfile),
    ClaudeLocalAgentSdk(ClaudeLocalAgentSdkProfile),
    ClaudeManagedAgents(ClaudeManagedAgentsProfile),
    Acp(AcpProfile),
}

/// Complete declared contract required for every external adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExternalAdapterManifest {
    pub adapter_id: String,
    pub bridge_type: BridgeType,
    pub upstream: BridgeRuntimeIdentity,
    pub license: BridgeLicenseRecord,
    pub transport: BridgeTransportContract,
    pub input: BridgeSchemaBound,
    pub output: BridgeSchemaBound,
    pub policy: BridgePolicy,
    pub health_probes: Vec<String>,
    pub failure_translation: BridgeFailureTranslation,
    pub state: BridgeStateContract,
    pub lifecycle: BridgeLifecycleTarget,
    pub profile: BridgeProfileContract,
}

impl ExternalAdapterManifest {
    /// Rejects incomplete, internally inconsistent, or profile-incompatible
    /// manifests before a caller can create an admission record.
    pub fn validate(&self) -> Result<(), BridgeAdmissionError> {
        validate_text(&self.adapter_id, "manifest.adapter_id")?;
        self.upstream.validate()?;
        for (value, field) in [
            (&self.license.license, "license.license"),
            (&self.license.source_ref, "license.source_ref"),
            (&self.license.reviewed_revision, "license.reviewed_revision"),
            (&self.input.schema_ref, "input.schema_ref"),
            (&self.output.schema_ref, "output.schema_ref"),
            (&self.policy.scope, "policy.scope"),
            (&self.policy.credentials, "policy.credentials"),
            (&self.state.exported_state_ref, "state.exported_state_ref"),
            (
                &self.state.rebuild_procedure_ref,
                "state.rebuild_procedure_ref",
            ),
            (
                &self.lifecycle.replacement_target,
                "lifecycle.replacement_target",
            ),
            (&self.lifecycle.removal_target, "lifecycle.removal_target"),
        ] {
            validate_text(value, field)?;
        }
        if self.input.max_bytes == 0 || self.output.max_bytes == 0 {
            return Err(BridgeAdmissionError::InvalidSchemaBound);
        }
        if self.health_probes.is_empty() {
            return Err(BridgeAdmissionError::InvalidCollection {
                field: "health_probes",
            });
        }
        validate_unique(&self.policy.effects, "policy.effects")?;
        validate_unique(&self.health_probes, "health_probes")?;
        for effect in &self.policy.effects {
            validate_text(effect, "policy.effect")?;
        }
        for probe in &self.health_probes {
            validate_text(probe, "health_probe")?;
        }
        self.failure_translation.validate()?;
        self.validate_profile()
    }

    fn validate_profile(&self) -> Result<(), BridgeAdmissionError> {
        match (&self.bridge_type, &self.profile) {
            (BridgeType::CodexAppServer, BridgeProfileContract::CodexAppServer(profile)) => {
                if !profile.stable_only {
                    return Err(BridgeAdmissionError::CodexSchemaMustBeStableOnly);
                }
                validate_sha256(
                    &profile.generated_schema_sha256,
                    "codex.generated_schema_sha256",
                )?;
                if profile.schema_bound_executable_sha256 != self.upstream.runtime_artifact_sha256 {
                    return Err(BridgeAdmissionError::CodexSchemaRuntimeMismatch);
                }
                validate_experimental_operations(&profile.experimental_operations)?;
                require_transport(
                    &self.transport,
                    BridgeTransport::StdioNdjson,
                    BridgeEndpointScope::LocalProcess,
                )
            }
            (BridgeType::OpenCode, BridgeProfileContract::OpenCode(profile)) => {
                if let Some(forensics) = &profile.internal_storage_forensics {
                    validate_text(&forensics.evidence_ref, "opencode.forensics.evidence_ref")?;
                    if !forensics.read_only || !forensics.degraded {
                        return Err(BridgeAdmissionError::OpenCodeForensicsMustBeDegraded);
                    }
                }
                if !self.transport.authenticated {
                    return Err(BridgeAdmissionError::TransportMustBeAuthenticated);
                }
                require_transport(
                    &self.transport,
                    BridgeTransport::AuthenticatedLoopbackHttpSse,
                    BridgeEndpointScope::Loopback,
                )
            }
            (
                BridgeType::ClaudeLocalAgentSdk,
                BridgeProfileContract::ClaudeLocalAgentSdk(profile),
            ) => {
                validate_text(&profile.sidecar_contract_ref, "claude.local_contract_ref")?;
                require_transport(
                    &self.transport,
                    BridgeTransport::SupervisedSidecarNdjson,
                    BridgeEndpointScope::LocalProcess,
                )
            }
            (
                BridgeType::ClaudeManagedAgents,
                BridgeProfileContract::ClaudeManagedAgents(profile),
            ) => {
                validate_text(&profile.managed_contract_ref, "claude.managed_contract_ref")?;
                require_transport(
                    &self.transport,
                    BridgeTransport::AuthenticatedHttp,
                    BridgeEndpointScope::RemoteService,
                )?;
                if !self.transport.authenticated {
                    return Err(BridgeAdmissionError::TransportMustBeAuthenticated);
                }
                Ok(())
            }
            (BridgeType::Acp, BridgeProfileContract::Acp(profile)) => {
                if profile.production_baseline != "v1" {
                    return Err(BridgeAdmissionError::AcpProductionBaselineMustBeV1);
                }
                validate_text(
                    &profile.exact_runtime_probe_ref,
                    "acp.exact_runtime_probe_ref",
                )?;
                validate_experimental_operations(&profile.v2_draft_operations)?;
                require_transport(
                    &self.transport,
                    BridgeTransport::Acp,
                    BridgeEndpointScope::AdapterRuntime,
                )
            }
            _ => Err(BridgeAdmissionError::ProfileTypeMismatch),
        }
    }
}

/// Validated, immutable manifest carrying one declared route/runtime identity.
/// The binding is descriptive; it is not proof of an observed runtime, a
/// process-local registry entry, or a production-promotion decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
pub struct BridgeAdmissionRecord {
    manifest: ExternalAdapterManifest,
    route: Route,
    runtime: BridgeRuntimeIdentity,
    capability_limitations: Vec<BridgeCapabilityLimitation>,
}

impl BridgeAdmissionRecord {
    /// Validates the complete manifest and binds it to the matching runtime
    /// identity and route before returning a record.
    pub fn new(
        manifest: ExternalAdapterManifest,
        route: Route,
        runtime: BridgeRuntimeIdentity,
        capability_limitations: Vec<BridgeCapabilityLimitation>,
    ) -> Result<Self, BridgeAdmissionError> {
        manifest.validate()?;
        route.validate()?;
        runtime.validate()?;
        if route.adapter_id != manifest.adapter_id {
            return Err(BridgeAdmissionError::RouteAdapterMismatch);
        }
        if runtime != manifest.upstream || route.fingerprint != runtime.fingerprint {
            return Err(BridgeAdmissionError::RuntimeRouteMismatch);
        }
        validate_capability_limitations(&capability_limitations)?;
        Ok(Self {
            manifest,
            route,
            runtime,
            capability_limitations,
        })
    }

    pub fn manifest(&self) -> &ExternalAdapterManifest {
        &self.manifest
    }

    pub fn route(&self) -> &Route {
        &self.route
    }

    pub fn runtime(&self) -> &BridgeRuntimeIdentity {
        &self.runtime
    }

    pub fn capability_limitations(&self) -> &[BridgeCapabilityLimitation] {
        &self.capability_limitations
    }
}

/// Reported failure kind bound to the same declared route/runtime identity.
/// Constructing it does not prove the failure occurred. Its reconciliation
/// state is never a completion or retry instruction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
pub struct BridgeFailureObservation {
    route: Route,
    runtime: BridgeRuntimeIdentity,
    kind: BridgeFailureKind,
    reconciliation: BridgeReconciliationState,
}

impl BridgeFailureObservation {
    pub fn new(
        admission: &BridgeAdmissionRecord,
        route: Route,
        runtime: BridgeRuntimeIdentity,
        kind: BridgeFailureKind,
    ) -> Result<Self, BridgeAdmissionError> {
        route.validate()?;
        runtime.validate()?;
        if route != admission.route || runtime != admission.runtime {
            return Err(BridgeAdmissionError::RuntimeRouteMismatch);
        }
        Ok(Self {
            route,
            runtime,
            kind,
            reconciliation: admission.manifest.failure_translation.state_for(kind),
        })
    }

    pub fn route(&self) -> &Route {
        &self.route
    }

    pub fn runtime(&self) -> &BridgeRuntimeIdentity {
        &self.runtime
    }

    pub fn kind(&self) -> BridgeFailureKind {
        self.kind
    }

    pub fn reconciliation(&self) -> BridgeReconciliationState {
        self.reconciliation
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BridgeAdmissionError {
    #[error(transparent)]
    Contract(#[from] crate::ContractError),
    #[error("{field} must be a 64-character SHA-256 hex digest")]
    InvalidSha256 { field: &'static str },
    #[error("schema bounds must be positive declared byte bounds")]
    InvalidSchemaBound,
    #[error("{field} collection is empty or contains duplicate items")]
    InvalidCollection { field: &'static str },
    #[error("manifest profile does not match its bridge type")]
    ProfileTypeMismatch,
    #[error("profile contract is invalid")]
    InvalidProfileContract,
    #[error("Codex App Server schema must be stable-only")]
    CodexSchemaMustBeStableOnly,
    #[error("Codex generated schema is not bound to the manifest executable")]
    CodexSchemaRuntimeMismatch,
    #[error("experimental operations must be disabled by default")]
    ExperimentalEnabledByDefault,
    #[error("experimental operation identity is duplicated")]
    DuplicateExperimentalOperation,
    #[error("OpenCode internal-storage forensics must be read-only and degraded")]
    OpenCodeForensicsMustBeDegraded,
    #[error("transport must be authenticated")]
    TransportMustBeAuthenticated,
    #[error("transport does not meet the profile boundary")]
    TransportProfileMismatch,
    #[error("ACP v1 must be the only production baseline")]
    AcpProductionBaselineMustBeV1,
    #[error("failure translation must preserve the typed reconciliation state")]
    InvalidFailureTranslation,
    #[error("route adapter does not match the manifest")]
    RouteAdapterMismatch,
    #[error("runtime identity does not match the exact admitted route")]
    RuntimeRouteMismatch,
    #[error("capability limitation list contains invalid or duplicate entries")]
    InvalidCapabilityLimitations,
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), BridgeAdmissionError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BridgeAdmissionError::InvalidSha256 { field });
    }
    Ok(())
}

fn validate_unique(values: &[String], field: &'static str) -> Result<(), BridgeAdmissionError> {
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(BridgeAdmissionError::InvalidCollection { field });
    }
    Ok(())
}

fn validate_experimental_operations(
    operations: &[BridgeExperimentalOperation],
) -> Result<(), BridgeAdmissionError> {
    let mut names = BTreeSet::new();
    for operation in operations {
        operation.validate()?;
        if !names.insert(&operation.operation) {
            return Err(BridgeAdmissionError::DuplicateExperimentalOperation);
        }
    }
    Ok(())
}

fn validate_capability_limitations(
    limitations: &[BridgeCapabilityLimitation],
) -> Result<(), BridgeAdmissionError> {
    let mut capabilities = BTreeSet::new();
    for limitation in limitations {
        validate_text(&limitation.capability, "capability_limitation.capability")?;
        validate_text(&limitation.detail, "capability_limitation.detail")?;
        if !capabilities.insert((&limitation.capability, limitation.kind)) {
            return Err(BridgeAdmissionError::InvalidCapabilityLimitations);
        }
    }
    Ok(())
}

fn require_transport(
    contract: &BridgeTransportContract,
    transport: BridgeTransport,
    endpoint_scope: BridgeEndpointScope,
) -> Result<(), BridgeAdmissionError> {
    if contract.transport != transport || contract.endpoint_scope != endpoint_scope {
        return Err(BridgeAdmissionError::TransportProfileMismatch);
    }
    Ok(())
}
