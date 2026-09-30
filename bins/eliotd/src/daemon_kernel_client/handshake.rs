//! Daemon-side Kernel handshake and wire validation.
//!
//! Architecture: A13.2 (Governor/Kernel authenticated IPC boundary), A13.8
//! (process-receipt-gated pre-admission).
//! Implementation: I1.8 (artifact-bound session), I2.16 (generation fencing),
//! I2.23 (typed contract payloads).
//! Kernel remains the sole process, Store, and canonical authority owner.

use eliot_contracts::EpochId;
#[cfg(windows)]
use eliot_contracts::{ArtifactId, ContractId, ContractVersion, ResourceGeneration};
use eliot_governor::{GovernorLaunchConfig, KernelGenerationSnapshot, KernelPortError};
#[cfg(windows)]
use eliot_protocol::{
    ClientHello, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolRange, ProtocolVersion,
    ServerHello,
};
#[cfg(windows)]
use eliot_runtime_contracts::{
    ModuleContract, ModuleGeneration, ModuleGenerationState, compare_published_projection,
};
use serde::Deserialize;
use thiserror::Error;

use super::KernelLaunchBinding;
use crate::{DaemonError, ELIOTD_RECEIPT_PENDING_REJECTION, PROTOCOL_VERSION, SERVICE_NAME};

#[derive(Debug, Error)]
pub(crate) enum KernelClientError {
    #[cfg(not(windows))]
    #[error("Kernel client is unavailable on this target")]
    Unsupported,
    #[error("Kernel client contract: {0}")]
    Contract(String),
    #[error("Kernel client unknown outcome: {0}")]
    Unknown(String),
    #[error("Kernel transport: {0}")]
    Transport(String),
    #[error("Kernel pre-admission transport: {0}")]
    PreAdmissionTransport(String),
    #[error("Kernel has not yet published the exact launched eliotd process receipt")]
    PreAdmissionPending,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum WireOutcome {
    Known {
        value: serde_json::Value,
        recovery: Option<serde_json::Value>,
    },
    Partial {
        reason: String,
        value: serde_json::Value,
    },
    Unknown {
        reason: String,
    },
    Error {
        code: String,
        reason: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelSnapshotWire {
    service: String,
    protocol: String,
    generation: u64,
    authority_epoch: EpochId,
    artifact_digest: String,
    protected_snapshot_digest: String,
}

pub(super) fn expected_snapshot(
    launch: &GovernorLaunchConfig,
) -> Result<KernelGenerationSnapshot, crate::DaemonError> {
    let snapshot = KernelGenerationSnapshot {
        service: launch.kernel.service.clone(),
        protocol: launch.kernel.protocol.clone(),
        generation: launch.kernel.generation,
        authority_epoch: launch.kernel.authority_epoch.clone(),
        artifact_digest: launch.kernel.artifact_digest.clone(),
        protected_snapshot_digest: launch.protected_snapshot_digest.clone(),
        principal: launch.kernel.principal.clone(),
    };
    snapshot
        .validate()
        .map_err(|error| crate::DaemonError::Kernel(error.to_string()))?;
    Ok(snapshot)
}

#[cfg(windows)]
impl super::DaemonKernelClient {
    pub(super) async fn snapshot_request(
        &self,
    ) -> Result<KernelGenerationSnapshot, KernelClientError> {
        let value = self
            .transact_async("snapshot", serde_json::json!({}))
            .await?;
        let wire: KernelSnapshotWire = serde_json::from_value(value)
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        let snapshot = KernelGenerationSnapshot {
            service: wire.service,
            protocol: wire.protocol,
            generation: ResourceGeneration::new(wire.generation)
                .map_err(|error| KernelClientError::Contract(error.to_string()))?,
            authority_epoch: wire.authority_epoch,
            artifact_digest: wire.artifact_digest,
            protected_snapshot_digest: wire.protected_snapshot_digest,
            principal: self.launch.kernel.principal.clone(),
        };
        snapshot
            .validate()
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        self.launch
            .kernel
            .admits(&snapshot)
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        Ok(snapshot)
    }
}

/// The daemon module's published I6.4 contract projection.
///
/// `module_contract.required_capabilities` carries runtime dependency edges onto
/// other hot modules. The `daemon` capability the daemon needs from the Kernel
/// is a handshake-requested capability (carried by `ClientHello.capabilities`),
/// not a runtime module-graph edge, so it is deliberately absent here: the two
/// lists are never conflated.
#[cfg(windows)]
pub(crate) fn declared_module_contract(
    module_id: ContractId,
    artifact_id: ArtifactId,
) -> ModuleContract {
    ModuleContract {
        module_id,
        version: ContractVersion::new(1, 0, 0),
        artifact_id,
        protocols: vec![PROTOCOL_VERSION.to_owned()],
        capabilities: Vec::new(),
        required_capabilities: Vec::new(),
        optional_capabilities: Vec::new(),
        advisory_capabilities: Vec::new(),
        state_owner: SERVICE_NAME.to_owned(),
        failure_domain: "daemon".to_owned(),
        owner: SERVICE_NAME.to_owned(),
        hot_replace: true,
        startup_after: Vec::new(),
        drain_before: Vec::new(),
        invalidation_triggers: Vec::new(),
        supervision_plan: "one_for_one".to_owned(),
        child_restart: "transient".to_owned(),
        restart_intensity: "3/10m".to_owned(),
        resource_profile: "background-medium".to_owned(),
        privacy_classes: vec!["PUBLIC".to_owned()],
        permissions: Vec::new(),
        health_contract: "health/eliotd-v1".to_owned(),
        checkpoint_contract: "checkpoint/daemon-v1".to_owned(),
        compatibility_state: "rebuildable".to_owned(),
        independent_test_profile: "module/eliotd".to_owned(),
        contract_fixture_set: "eliot.daemon.v1/daemon".to_owned(),
        affected_test_tags: vec!["eliotd".to_owned(), "daemon".to_owned()],
        architecture: Vec::new(),
        telemetry: "telemetry/eliotd-v1".to_owned(),
        removal_boundary: "eliotd".to_owned(),
    }
}

/// Admits the daemon's immutable runtime manifest and returns the module
/// contract projection the Kernel handshake must publish.
///
/// The manifest bytes are loaded from the admitted artifact location through the
/// protected path lease and admitted against the accepted build identity; the
/// publisher's declaration is then compared field-by-field with the contract
/// those exact bytes carry, so a substituted or edited manifest is refused
/// rather than published.
///
/// This is the daemon's manifest admission boundary. It is not yet reached from
/// the live startup path because no build/package owner stages the manifest
/// beside the artifact. The release bundler
/// (`scripts/build-eliot-windows-x64-release.ps1`) is that owner and is not
/// this issue's; the wiring is blocked on it.
#[cfg(windows)]
pub fn admitted_daemon_module_contract(
    accepted_artifact_sha256: &str,
) -> Result<ModuleContract, DaemonError> {
    let admitted = crate::daemon_config::admit_daemon_module_manifest(accepted_artifact_sha256)?;
    let contract =
        declared_module_contract(admitted.module_id.clone(), admitted.artifact_id.clone());
    compare_published_projection(&admitted, &contract)
        .map_err(|error| DaemonError::LaunchConfig(error.to_string()))?;
    Ok(contract)
}

#[cfg(windows)]
pub(super) fn client_hello(
    binding: &KernelLaunchBinding,
) -> Result<ClientHello, KernelClientError> {
    let module_id = ContractId::new("eliotd")
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
    let artifact_id = ArtifactId::new(binding.daemon_artifact_sha256.as_str())
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
    let contract = admitted_daemon_module_contract(binding.daemon_artifact_sha256.as_str())
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
    let generation = ModuleGeneration {
        module_id,
        generation: binding.module_generation,
        artifact_id,
        state: ModuleGenerationState::Starting,
        health: eliot_runtime_contracts::HealthVector::healthy(),
        state_fence: binding.state_fence.clone(),
    };
    Ok(ClientHello {
        protocol_range: ProtocolRange {
            minimum: ProtocolVersion::CURRENT,
            maximum: ProtocolVersion::CURRENT,
        },
        module_bridge_identity: SERVICE_NAME.to_owned(),
        artifact_hash: generation.artifact_id.clone(),
        module_contract: contract,
        module_generation: generation,
        launch_nonce: binding.launch_nonce.clone(),
        capabilities: vec!["daemon".to_owned()],
        privacy_classes: vec!["PUBLIC".to_owned()],
        max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES)
            .map_err(|_| KernelClientError::Contract("maximum frame exceeds u32".to_owned()))?,
        authority_epoch: binding.authority_epoch.clone(),
    })
}

#[cfg(windows)]
pub(crate) fn is_pre_admission_pending_rejection(
    frame: &Frame,
    expected_connection_id: &str,
) -> bool {
    if frame.validate().is_err()
        || frame.connection_id != expected_connection_id
        || frame.kind != FrameKind::Control
        || frame.message_type != MessageType::Fatal
        || frame.request_id.is_some()
        || frame.request_identity.is_some()
    {
        return false;
    }
    let ProtocolPayload::Json(serde_json::Value::Object(payload)) = &frame.payload else {
        return false;
    };
    payload.len() == 1
        && payload
            .get("rejection_reason")
            .and_then(serde_json::Value::as_str)
            == Some(ELIOTD_RECEIPT_PENDING_REJECTION)
}

#[cfg(windows)]
pub(crate) fn validate_server_hello(
    launch: &GovernorLaunchConfig,
    binding: &KernelLaunchBinding,
    hello: &ServerHello,
) -> Result<(), KernelClientError> {
    hello
        .validate()
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
    if hello.selected_protocol != ProtocolVersion::CURRENT
        || !hello
            .authority_epoch
            .is_same_authority(&launch.kernel.authority_epoch)
        || hello.session_principal_binding
            != format!(
                "sid={};session={}",
                binding.expected_kernel_sid, binding.expected_kernel_session_id
            )
    {
        return Err(KernelClientError::Contract(
            "Kernel ServerHello principal/protocol/epoch mismatch".to_owned(),
        ));
    }
    let snapshot: KernelSnapshotWire = serde_json::from_value(hello.config_snapshot.clone())
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
    if snapshot.service != launch.kernel.service
        || snapshot.protocol != launch.kernel.protocol
        || snapshot.generation != launch.kernel.generation.value()
        || !snapshot
            .authority_epoch
            .is_same_authority(&launch.kernel.authority_epoch)
        || snapshot.artifact_digest != launch.kernel.artifact_digest
        || snapshot.protected_snapshot_digest != launch.protected_snapshot_digest
        || snapshot.protected_snapshot_digest != launch.kernel.protected_snapshot_digest
    {
        return Err(KernelClientError::Contract(
            "Kernel ServerHello generation snapshot mismatch".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn operation_payload(
    operation: &str,
    payload: serde_json::Value,
) -> Result<serde_json::Value, KernelClientError> {
    let serde_json::Value::Object(mut object) = payload else {
        return Err(KernelClientError::Contract(
            "Kernel application payload must be an object".to_owned(),
        ));
    };
    object.insert(
        "operation".to_owned(),
        serde_json::Value::String(operation.to_owned()),
    );
    Ok(serde_json::Value::Object(object))
}

pub(crate) fn kernel_port_error(error: KernelClientError) -> KernelPortError {
    match error {
        KernelClientError::Contract(error) => KernelPortError::Contract(error),
        KernelClientError::Unknown(error) => KernelPortError::Unknown(error),
        KernelClientError::Transport(error) => KernelPortError::NotAdmitted(error),
        KernelClientError::PreAdmissionTransport(error) => KernelPortError::NotAdmitted(error),
        KernelClientError::PreAdmissionPending => KernelPortError::NotAdmitted(
            "Kernel has not published the exact launched process receipt".to_owned(),
        ),
        #[cfg(not(windows))]
        KernelClientError::Unsupported => {
            KernelPortError::NotAdmitted("Windows Kernel transport is required".to_owned())
        }
    }
}
