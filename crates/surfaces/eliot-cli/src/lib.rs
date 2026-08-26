//! Provider-neutral generated command catalogue and thin ELIOT client surface.
//!
//! This crate owns command descriptions, typed request/response correlation and
//! deterministic help/schema projections. It does not open transports, start
//! processes, write a store, mint authority or decide task completion.

#![forbid(unsafe_code)]

use std::{collections::BTreeSet, fmt::Write as _, path::Path};

use eliot_protocol::RequestIdentity;
use eliot_receipts::{EffectClass, ProofCeiling};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

/// Stable generated catalogue identity for A-11 plan-v2.
pub const CATALOGUE_NAME: &str = "eliot.cli.commands";
/// Catalogue revision emitted by help and schema projections.
pub const CATALOGUE_REVISION: &str = "a11-plan-v2";
/// Schema projection identity.
pub const SCHEMA_VERSION: &str = "eliot-cli-schema-v1";
/// MCP surface revision consumed by the CLI catalogue edge.
pub const MCP_SURFACE_CONTRACT_REVISION: &str = eliot_mcp::CONTRACT_REVISION;
/// Stable A-08 [`eliot_controlboard::PLAN_GAP`] marker bound into this
/// catalogue edge while its admitted providers remain uninjected by
/// composition.
pub const CONTROLBOARD_PLAN_GAP: &str = eliot_controlboard::PLAN_GAP;

/// Canonical command identifiers from the first-line command projection.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, JsonSchema, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum CommandId {
    SystemSnapshot,
    BootstrapBrief,
    RecoveryStatus,
    Ui,
    Dashboard,
    DevImpactChanged,
    DevCheckChanged,
    DevTestChanged,
    DevPulse,
    InstrumentRun,
    ModuleValidate,
    ModuleTest,
    ModuleContractTest,
    ModuleEdgeTest,
    ModuleBuild,
    ModuleStage,
    ModuleCanary,
    ModulePromote,
    ModuleRollback,
    ReleaseVerify,
    DoctorIntegration,
    BackupCreate,
    BackupVerify,
    BackupRestoreTest,
    MaintenanceRun,
}

impl CommandId {
    /// Returns the canonical generated identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemSnapshot => "system-snapshot",
            Self::BootstrapBrief => "bootstrap-brief",
            Self::RecoveryStatus => "recovery-status",
            Self::Ui => "ui",
            Self::Dashboard => "dashboard",
            Self::DevImpactChanged => "dev-impact-changed",
            Self::DevCheckChanged => "dev-check-changed",
            Self::DevTestChanged => "dev-test-changed",
            Self::DevPulse => "dev-pulse",
            Self::InstrumentRun => "instrument-run",
            Self::ModuleValidate => "module-validate",
            Self::ModuleTest => "module-test",
            Self::ModuleContractTest => "module-contract-test",
            Self::ModuleEdgeTest => "module-edge-test",
            Self::ModuleBuild => "module-build",
            Self::ModuleStage => "module-stage",
            Self::ModuleCanary => "module-canary",
            Self::ModulePromote => "module-promote",
            Self::ModuleRollback => "module-rollback",
            Self::ReleaseVerify => "release-verify",
            Self::DoctorIntegration => "doctor-integration",
            Self::BackupCreate => "backup-create",
            Self::BackupVerify => "backup-verify",
            Self::BackupRestoreTest => "backup-restore-test",
            Self::MaintenanceRun => "maintenance-run",
        }
    }
}

/// Closed typed argument union for every catalogue command.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandArguments {
    SystemSnapshot {
        repo_root: String,
        output_path: String,
    },
    BootstrapBrief {
        work_unit: String,
        repo_root: String,
    },
    RecoveryStatus,
    Ui,
    Dashboard,
    DevImpactChanged,
    DevCheckChanged,
    DevTestChanged,
    DevPulse {
        objective_id: String,
    },
    InstrumentRun {
        profile: String,
        scope: Option<String>,
    },
    ModuleValidate {
        module_id: String,
    },
    ModuleTest {
        module_id: String,
    },
    ModuleContractTest {
        module_id: String,
        against: String,
    },
    ModuleEdgeTest {
        edge_id: String,
    },
    ModuleBuild {
        module_id: String,
    },
    ModuleStage {
        artifact: String,
    },
    ModuleCanary {
        module_id: String,
        scope: String,
    },
    ModulePromote {
        module_id: String,
        generation: String,
    },
    ModuleRollback {
        module_id: String,
    },
    ReleaseVerify,
    DoctorIntegration {
        profile: String,
    },
    BackupCreate,
    BackupVerify,
    BackupRestoreTest,
    MaintenanceRun,
}

impl CommandArguments {
    fn command_id(&self) -> CommandId {
        match self {
            Self::SystemSnapshot { .. } => CommandId::SystemSnapshot,
            Self::BootstrapBrief { .. } => CommandId::BootstrapBrief,
            Self::RecoveryStatus => CommandId::RecoveryStatus,
            Self::Ui => CommandId::Ui,
            Self::Dashboard => CommandId::Dashboard,
            Self::DevImpactChanged => CommandId::DevImpactChanged,
            Self::DevCheckChanged => CommandId::DevCheckChanged,
            Self::DevTestChanged => CommandId::DevTestChanged,
            Self::DevPulse { .. } => CommandId::DevPulse,
            Self::InstrumentRun { .. } => CommandId::InstrumentRun,
            Self::ModuleValidate { .. } => CommandId::ModuleValidate,
            Self::ModuleTest { .. } => CommandId::ModuleTest,
            Self::ModuleContractTest { .. } => CommandId::ModuleContractTest,
            Self::ModuleEdgeTest { .. } => CommandId::ModuleEdgeTest,
            Self::ModuleBuild { .. } => CommandId::ModuleBuild,
            Self::ModuleStage { .. } => CommandId::ModuleStage,
            Self::ModuleCanary { .. } => CommandId::ModuleCanary,
            Self::ModulePromote { .. } => CommandId::ModulePromote,
            Self::ModuleRollback { .. } => CommandId::ModuleRollback,
            Self::ReleaseVerify => CommandId::ReleaseVerify,
            Self::DoctorIntegration { .. } => CommandId::DoctorIntegration,
            Self::BackupCreate => CommandId::BackupCreate,
            Self::BackupVerify => CommandId::BackupVerify,
            Self::BackupRestoreTest => CommandId::BackupRestoreTest,
            Self::MaintenanceRun => CommandId::MaintenanceRun,
        }
    }

    fn validate_text(value: &str, field: &'static str) -> Result<(), CliError> {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(CliError::InvalidArgument { field });
        }
        Ok(())
    }

    fn validate_absolute_path(value: &str, field: &'static str) -> Result<(), CliError> {
        Self::validate_text(value, field)?;
        if !Path::new(value).is_absolute() {
            return Err(CliError::InvalidArgument { field });
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), CliError> {
        match self {
            Self::SystemSnapshot {
                repo_root,
                output_path,
            } => {
                Self::validate_absolute_path(repo_root, "repo_root")?;
                Self::validate_absolute_path(output_path, "output_path")
            }
            Self::BootstrapBrief {
                work_unit,
                repo_root,
            } => {
                Self::validate_absolute_path(work_unit, "work_unit")?;
                Self::validate_absolute_path(repo_root, "repo_root")
            }
            Self::DevPulse { objective_id } => Self::validate_text(objective_id, "objective_id"),
            Self::InstrumentRun { profile, scope } => {
                Self::validate_text(profile, "profile")?;
                if let Some(scope) = scope {
                    Self::validate_text(scope, "scope")?;
                }
                Ok(())
            }
            Self::ModuleValidate { module_id }
            | Self::ModuleTest { module_id }
            | Self::ModuleBuild { module_id }
            | Self::ModuleRollback { module_id } => Self::validate_text(module_id, "module_id"),
            Self::ModuleContractTest { module_id, against } => {
                Self::validate_text(module_id, "module_id")?;
                Self::validate_text(against, "against")
            }
            Self::ModuleEdgeTest { edge_id } => Self::validate_text(edge_id, "edge_id"),
            Self::ModuleStage { artifact } => Self::validate_text(artifact, "artifact"),
            Self::ModuleCanary { module_id, scope } => {
                Self::validate_text(module_id, "module_id")?;
                Self::validate_text(scope, "scope")
            }
            Self::ModulePromote {
                module_id,
                generation,
            } => {
                Self::validate_text(module_id, "module_id")?;
                Self::validate_text(generation, "generation")
            }
            Self::DoctorIntegration { profile } => Self::validate_text(profile, "profile"),
            Self::RecoveryStatus
            | Self::Ui
            | Self::Dashboard
            | Self::DevImpactChanged
            | Self::DevCheckChanged
            | Self::DevTestChanged
            | Self::ReleaseVerify
            | Self::BackupCreate
            | Self::BackupVerify
            | Self::BackupRestoreTest
            | Self::MaintenanceRun => Ok(()),
        }
    }
}

/// Exact unavailable state for an advertised but not-yet-reachable command.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum UnavailableReason {
    /// The capability is named by the plan but its owner has not been accepted.
    PlanGap {
        missing_work_id: String,
        dependency: String,
    },
    /// The stable surface is intentionally not admitted in this profile.
    Unsupported { dependency: String, detail: String },
}

/// Result of one thin-client operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum CommandResult {
    Help {
        text: String,
    },
    Schema {
        json: String,
    },
    /// A response projected by the authenticated Kernel application port.
    ///
    /// The payload is an inert projection; this crate never interprets it as
    /// canonical state or grants authority from it.
    Forwarded {
        payload: Value,
    },
    /// A locally compiled bootstrap brief with explicit normative coverage.
    BootstrapBrief {
        brief: Box<eliot_bootstrap::BootstrapBrief>,
    },
    Unimplemented {
        architecture_anchor: String,
        work_item_id: String,
        detail: String,
    },
    Unavailable {
        reason: UnavailableReason,
    },
}

/// Request crossing the public client boundary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRequest {
    pub request: RequestIdentity,
    pub command: CommandId,
    pub arguments: CommandArguments,
}

impl CommandRequest {
    /// Validates full provider identity plus command/argument bijection.
    pub fn validate(&self) -> Result<(), CliError> {
        self.request
            .validate()
            .map_err(|error| CliError::Protocol(error.to_string()))?;
        self.arguments.validate()?;
        if self.arguments.command_id() != self.command {
            return Err(CliError::ArgumentCommandMismatch);
        }
        Ok(())
    }
}

/// Correlated response returned by a pure client operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandResponse {
    pub request: RequestIdentity,
    pub command: CommandId,
    pub effect: EffectClass,
    pub proof_ceiling: ProofCeiling,
    pub result: CommandResult,
}

/// Provider-neutral application front door owned by Kernel composition.
///
/// `eliot` is only a caller of this seam. Implementations must authenticate
/// the transport and return a response bound to the exact request; they may
/// not widen command arguments, effects, or proof ceilings.
pub trait CommandPort {
    /// Dispatches one already-typed command request through the owning front
    /// door.
    fn dispatch(&mut self, request: &CommandRequest) -> Result<CommandResponse, CommandPortError>;
}

/// Failure at the neutral application-port boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CommandPortError {
    /// Kernel has not admitted an application front door for this profile.
    #[error("kernel application front door is closed: {contract}")]
    FrontDoorClosed { contract: &'static str },
    /// The owning provider rejected the exact request without a local retry.
    #[error("kernel application front door rejected the request: {0}")]
    Rejected(String),
}

/// Authenticated local Kernel front-door client shared by Stage 7 surfaces.
///
/// The client owns only transport/session proof. It does not interpret a
/// response as authority; callers must validate the response against their
/// own provider contract. The protected configuration is installed by the
/// Kernel/installation owner and supplies the expected service SID/session as
/// well as the exact EBP `ClientHello` binding.
pub mod kernel_client {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use eliot_contracts::RequestId;
    use eliot_ipc::{
        DeliveryOutcome, NamedPipeTransport, TransportLimits, client_hello_frame,
        decode_server_hello_frame,
    };
    use eliot_platform_windows::{
        NamedPipePeerExpectation, ProtectedPathLease, protected_program_data_path,
    };
    use eliot_protocol::{
        ClientHello, EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload,
        ProtocolVersion, RequestIdentity, ServerHello,
    };
    use serde::Deserialize;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use thiserror::Error;

    const KERNEL_FRONT_DOOR_PIPE: &str = r"\\.\pipe\eliot\kernel\frontdoor";
    const CONFIG_RELATIVE_PATH: &str = "Eliot/kernel/application-client.json";
    const CONFIG_LIMIT: u64 = 64 * 1024;
    const OPERATION_LIMIT: usize = 160;
    const KERNEL_SERVICE_NAME: &str = "eliot-kernel";
    const KERNEL_PROTOCOL_VERSION: &str = "eliot.kernel.v1";

    /// Protected installation-provided connection declaration.
    #[derive(Clone, Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct KernelClientConfig {
        /// Stable connection identity assigned by the Kernel owner.
        pub connection_id: String,
        /// SID of the Kernel service process expected at the pipe peer.
        pub expected_kernel_sid: String,
        /// Session id of the Kernel service process expected at the pipe peer.
        pub expected_kernel_session_id: u32,
        /// Exact client handshake declaration approved for this installation.
        pub client_hello: ClientHello,
        /// SHA-256 of canonical JSON `client_hello` bytes from the approved
        /// installation manifest.
        pub client_hello_sha256: String,
        /// Protected principal binding selected by the Kernel owner.
        pub expected_server_principal_binding: String,
        /// Protected authority epoch for the configured module generation.
        pub expected_authority_epoch: u64,
        /// Numeric identity of the expected immutable module generation.
        pub expected_generation: u64,
        /// Digest/identity of the expected server artifact.
        pub expected_artifact_digest: String,
        /// SHA-256 of the exact canonical JSON `ServerHello.config_snapshot`.
        pub expected_config_snapshot_sha256: String,
    }

    /// Failure at the authenticated application front door.
    #[derive(Clone, Debug, Eq, Error, PartialEq)]
    pub enum KernelClientError {
        /// No protected front-door configuration is available on this host.
        #[error("kernel application front door is closed: {0}")]
        FrontDoorClosed(&'static str),
        /// The protected configuration or operation was rejected locally.
        #[error("kernel client configuration rejected: {0}")]
        Configuration(String),
        /// A request lacked the exact EBP identity required by the gateway.
        #[error("kernel request identity is missing")]
        MissingRequestIdentity,
        /// The authenticated provider rejected or fenced the operation.
        #[error("kernel front door rejected the request: {0}")]
        Rejected(String),
        /// The request may have reached the provider, but its outcome was not
        /// proven by an exact typed reply and must be reconciled by operation.
        #[error("kernel front door outcome is unknown: {0}")]
        UnknownOutcome(String),
    }

    /// Provider-neutral request for the interactive Operator contour.  The
    /// Kernel must bind this request to its admitted handshake snapshot; the
    /// CLI never supplies a path, image, digest, capability, fence, or clock.
    #[derive(Clone, Debug, Deserialize, serde::Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct OperatorLaunchRequest {
        pub role: String,
        pub capabilities: Vec<String>,
    }

    /// Provider-neutral launch receipt returned by the User Broker/Kernel
    /// boundary.  Its fields intentionally remain opaque to the CLI.
    #[derive(Clone, Debug, Deserialize, serde::Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct OperatorLaunchReceipt {
        pub operation_id: String,
        pub status: String,
        pub receipt: Value,
    }

    /// Exact server-owned configuration snapshot carried by `ServerHello`.
    /// This is deliberately closed: a plausible arbitrary JSON object cannot
    /// stand in for the Kernel's generation, authority and artifact binding.
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct KernelConfigSnapshot {
        service: String,
        protocol: String,
        generation: u64,
        authority_epoch: u64,
        artifact_digest: String,
    }

    /// One short-lived authenticated session. It is intentionally not a
    /// durable authority token and reconnects for each operation.
    pub struct KernelClient {
        config: KernelClientConfig,
        request_identity: Option<RequestIdentity>,
        #[cfg(windows)]
        config_lease: ProtectedPathLease,
    }

    impl KernelClient {
        /// Loads the installation-owned protected client declaration.
        pub fn load() -> Result<Self, KernelClientError> {
            #[cfg(not(windows))]
            {
                return Err(KernelClientError::FrontDoorClosed(
                    "Windows authenticated Kernel front door",
                ));
            }
            #[cfg(windows)]
            {
                let path = protected_program_data_path(CONFIG_RELATIVE_PATH)
                    .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
                let lease = ProtectedPathLease::open_existing_absolute(&path)
                    .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
                let bytes = lease
                    .read_bounded(CONFIG_LIMIT)
                    .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
                let config: KernelClientConfig =
                    serde_json::from_slice(&bytes).map_err(|error| {
                        KernelClientError::Configuration(format!(
                            "decode Kernel client configuration: {error}"
                        ))
                    })?;
                validate_config(&config)?;
                Ok(Self {
                    config,
                    request_identity: None,
                    config_lease: lease,
                })
            }
        }

        /// Binds the exact caller identity for the next application request.
        pub fn set_request_identity(&mut self, identity: RequestIdentity) {
            self.request_identity = Some(identity);
        }

        /// Requests the broker-owned Operator launch.  This remains closed
        /// until Kernel advertises the operation and its handshake snapshot
        /// includes the current fence and observed clock needed to construct
        /// the request identity.  No local identity is a valid substitute.
        pub fn ensure_operator_launch(&mut self) -> Result<Value, KernelClientError> {
            let _request = OperatorLaunchRequest {
                role: "human_operator".to_owned(),
                capabilities: vec![
                    "controlboard.read".to_owned(),
                    "operator.command".to_owned(),
                ],
            };
            Err(KernelClientError::FrontDoorClosed(
                "Kernel user-broker Operator launch contract with admitted fence/clock snapshot",
            ))
        }

        /// Performs a bounded authenticated health exchange with Kernel.
        pub fn probe(&mut self) -> Result<Value, KernelClientError> {
            #[cfg(not(windows))]
            {
                Err(KernelClientError::FrontDoorClosed(
                    "Windows authenticated Kernel front door",
                ))
            }
            #[cfg(windows)]
            {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| KernelClientError::Rejected(error.to_string()))?;
                runtime.block_on(self.probe_async())
            }
        }

        /// Sends one exact provider operation through the authenticated EBP
        /// Execute seam. The operation string is a contract selector, not a
        /// local command authority.
        pub fn transact_json(
            &mut self,
            operation: &str,
            payload: Value,
        ) -> Result<Value, KernelClientError> {
            validate_operation(operation)?;
            let identity = self
                .request_identity
                .clone()
                .ok_or(KernelClientError::MissingRequestIdentity)?;
            #[cfg(not(windows))]
            {
                let _ = (identity, payload);
                Err(KernelClientError::FrontDoorClosed(
                    "Windows authenticated Kernel front door",
                ))
            }
            #[cfg(windows)]
            {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| KernelClientError::Rejected(error.to_string()))?;
                runtime.block_on(self.transact_async(operation, payload, identity))
            }
        }

        #[cfg(windows)]
        async fn connect(
            &self,
        ) -> Result<(NamedPipeTransport, TransportLimits), KernelClientError> {
            self.config_lease
                .verify_stable_identity()
                .and_then(|()| self.config_lease.verify_path_identity())
                .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
            let expectation = NamedPipePeerExpectation::new(
                &self.config.expected_kernel_sid,
                self.config.expected_kernel_session_id,
            )
            .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
            let mut transport = NamedPipeTransport::connect_authenticated(
                KERNEL_FRONT_DOOR_PIPE,
                Duration::from_secs(5),
                &expectation,
            )
            .await
            .map_err(|error| KernelClientError::Rejected(error.to_string()))?;
            let limits = TransportLimits::default();
            let hello = client_hello_frame(&self.config.connection_id, &self.config.client_hello)
                .map_err(|error| KernelClientError::Rejected(error.to_string()))?;
            require_delivery(
                transport.send_frame(&hello, limits).await,
                "Kernel client hello",
            )?;
            let server = transport
                .receive_frame(limits)
                .await
                .map_err(|error| KernelClientError::Rejected(error.to_string()))?;
            let hello = decode_server_hello_frame(&server, &self.config.connection_id)
                .map_err(|error| KernelClientError::Rejected(error.to_string()))?;
            validate_server_hello(&self.config, &hello)?;
            Ok((transport, limits))
        }

        #[cfg(windows)]
        async fn probe_async(&self) -> Result<Value, KernelClientError> {
            let (mut transport, limits) = self.connect().await?;
            let frame = Frame {
                protocol_version: ProtocolVersion::CURRENT,
                encoding_profile: EncodingProfile::JsonV1,
                connection_id: self.config.connection_id.clone(),
                request_id: None,
                kind: FrameKind::Heartbeat,
                message_type: MessageType::Health,
                request_identity: None,
                payload: ProtocolPayload::Json(json!({"status": "probe"})),
                trace_context: BTreeMap::new(),
            };
            require_delivery(
                transport.send_frame(&frame, limits).await,
                "Kernel health probe",
            )?;
            let response = transport
                .receive_frame(limits)
                .await
                .map_err(|error| KernelClientError::UnknownOutcome(error.to_string()))?;
            validate_health_response(&self.config.connection_id, &response)
        }

        #[cfg(windows)]
        async fn transact_async(
            &self,
            operation: &str,
            payload: Value,
            identity: RequestIdentity,
        ) -> Result<Value, KernelClientError> {
            let (mut transport, limits) = self.connect().await?;
            let request_id = identity.request.metadata.request_id.clone();
            let frame = Frame {
                protocol_version: ProtocolVersion::CURRENT,
                encoding_profile: EncodingProfile::JsonV1,
                connection_id: self.config.connection_id.clone(),
                request_id: Some(identity.request.metadata.request_id.clone()),
                kind: FrameKind::Request,
                message_type: MessageType::Execute,
                request_identity: Some(identity),
                payload: ProtocolPayload::Json(json!({
                    "operation": operation,
                    "payload": payload,
                })),
                trace_context: BTreeMap::new(),
            };
            require_delivery(
                transport.send_frame(&frame, limits).await,
                "Kernel application request",
            )?;
            let response = transport
                .receive_frame(limits)
                .await
                .map_err(|error| KernelClientError::UnknownOutcome(error.to_string()))?;
            validate_result_response(&self.config.connection_id, &request_id, &response)
        }
    }

    fn validate_config(config: &KernelClientConfig) -> Result<(), KernelClientError> {
        if config.connection_id.trim().is_empty()
            || config.connection_id.chars().any(char::is_control)
        {
            return Err(KernelClientError::Configuration(
                "Kernel connection identity is invalid".to_owned(),
            ));
        }
        if config.expected_kernel_sid.trim().is_empty()
            || config.expected_kernel_sid.chars().any(char::is_control)
        {
            return Err(KernelClientError::Configuration(
                "Kernel service SID is invalid".to_owned(),
            ));
        }
        NamedPipePeerExpectation::new(
            &config.expected_kernel_sid,
            config.expected_kernel_session_id,
        )
        .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
        config
            .client_hello
            .validate()
            .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
        if config.client_hello_sha256.len() != 64
            || !config
                .client_hello_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(KernelClientError::Configuration(
                "Kernel client hello digest is invalid".to_owned(),
            ));
        }
        let hello_bytes = serde_json::to_vec(&config.client_hello)
            .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
        let expected = format!("{:x}", Sha256::digest(hello_bytes));
        if !config.client_hello_sha256.eq_ignore_ascii_case(&expected) {
            return Err(KernelClientError::Configuration(
                "Kernel client hello digest does not match approved bytes".to_owned(),
            ));
        }
        if config.expected_server_principal_binding.trim().is_empty()
            || config
                .expected_server_principal_binding
                .chars()
                .any(char::is_control)
            || config.expected_artifact_digest.trim().is_empty()
            || config
                .expected_artifact_digest
                .chars()
                .any(char::is_control)
            || config.expected_artifact_digest.len() != 64
            || !config
                .expected_artifact_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(KernelClientError::Configuration(
                "Kernel server binding declaration is invalid".to_owned(),
            ));
        }
        if config.expected_authority_epoch == 0
            || config.expected_generation == 0
            || config.expected_config_snapshot_sha256.len() != 64
            || !config
                .expected_config_snapshot_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(KernelClientError::Configuration(
                "Kernel server binding digest/epoch is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_server_hello(
        config: &KernelClientConfig,
        hello: &ServerHello,
    ) -> Result<(), KernelClientError> {
        hello
            .validate()
            .map_err(|error| KernelClientError::Rejected(error.to_string()))?;
        if hello.rejection_reason.is_some()
            || hello.selected_protocol != ProtocolVersion::CURRENT
            || hello.session_principal_binding != config.expected_server_principal_binding
            || hello.authority_epoch.value() != config.expected_authority_epoch
        {
            return Err(KernelClientError::Rejected(
                "Kernel ServerHello is not bound to the protected authority".to_owned(),
            ));
        }
        validate_server_snapshot(
            hello,
            config.expected_authority_epoch,
            config.expected_generation,
            &config.expected_artifact_digest,
        )?;
        let snapshot_bytes = serde_json::to_vec(&hello.config_snapshot)
            .map_err(|error| KernelClientError::Rejected(error.to_string()))?;
        let snapshot_digest = format!("{:x}", Sha256::digest(snapshot_bytes));
        if !snapshot_digest.eq_ignore_ascii_case(&config.expected_config_snapshot_sha256) {
            return Err(KernelClientError::Rejected(
                "Kernel ServerHello configuration snapshot digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_server_snapshot(
        hello: &ServerHello,
        expected_authority_epoch: u64,
        expected_generation: u64,
        expected_artifact_digest: &str,
    ) -> Result<(), KernelClientError> {
        let snapshot: KernelConfigSnapshot = serde_json::from_value(hello.config_snapshot.clone())
            .map_err(|error| {
                KernelClientError::Rejected(format!(
                    "Kernel ServerHello configuration snapshot shape is invalid: {error}"
                ))
            })?;
        if snapshot.service != KERNEL_SERVICE_NAME
            || snapshot.protocol != KERNEL_PROTOCOL_VERSION
            || snapshot.generation == 0
            || snapshot.generation != expected_generation
            || snapshot.authority_epoch != expected_authority_epoch
            || hello.authority_epoch.value() != snapshot.authority_epoch
            || snapshot.artifact_digest.len() != 64
            || !snapshot
                .artifact_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || snapshot.artifact_digest != expected_artifact_digest
        {
            return Err(KernelClientError::Rejected(
                "Kernel ServerHello generation/authority/artifact binding mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_health_response(
        connection_id: &str,
        response: &Frame,
    ) -> Result<Value, KernelClientError> {
        response
            .validate()
            .map_err(|error| KernelClientError::UnknownOutcome(error.to_string()))?;
        if response.protocol_version != ProtocolVersion::CURRENT
            || response.connection_id != connection_id
            || response.kind != FrameKind::Heartbeat
            || response.message_type != MessageType::Health
            || response.request_id.is_some()
            || response.request_identity.is_some()
        {
            return Err(KernelClientError::UnknownOutcome(
                "Kernel health reply binding mismatch".to_owned(),
            ));
        }
        match &response.payload {
            ProtocolPayload::Json(value) if value.get("rejection_reason").is_none() => {
                Ok(value.clone())
            }
            ProtocolPayload::Json(_) => Err(KernelClientError::Rejected(
                "Kernel health reply was rejected".to_owned(),
            )),
            _ => Err(KernelClientError::UnknownOutcome(
                "Kernel health response was not typed JSON".to_owned(),
            )),
        }
    }

    fn validate_result_response(
        connection_id: &str,
        request_id: &RequestId,
        response: &Frame,
    ) -> Result<Value, KernelClientError> {
        response
            .validate()
            .map_err(|error| KernelClientError::UnknownOutcome(error.to_string()))?;
        if response.protocol_version != ProtocolVersion::CURRENT
            || response.connection_id != connection_id
            || response.request_id.as_ref() != Some(request_id)
            || response.kind != FrameKind::Response
            || response.message_type != MessageType::Result
            || response.request_identity.is_some()
        {
            return Err(KernelClientError::UnknownOutcome(
                "Kernel result reply binding mismatch".to_owned(),
            ));
        }
        match &response.payload {
            ProtocolPayload::Json(value) => {
                if value.get("rejection_reason").is_some() {
                    return Err(KernelClientError::Rejected(
                        "Kernel result reply was rejected".to_owned(),
                    ));
                }
                Ok(value.clone())
            }
            _ => Err(KernelClientError::UnknownOutcome(
                "Kernel result response was not typed JSON".to_owned(),
            )),
        }
    }

    fn validate_operation(operation: &str) -> Result<(), KernelClientError> {
        if operation.trim().is_empty()
            || operation.len() > OPERATION_LIMIT
            || operation.chars().any(char::is_control)
        {
            return Err(KernelClientError::Configuration(
                "Kernel operation selector is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    // The platform delivery helper must remain cfg-gated beside production code;
    // fixtures intentionally fail immediately for invalid static identities.
    #[allow(clippy::expect_used, clippy::items_after_test_module)]
    mod tests {
        use super::*;
        use eliot_contracts::AuthorityEpoch;

        fn server_hello(snapshot: Value) -> ServerHello {
            ServerHello {
                selected_protocol: ProtocolVersion::CURRENT,
                session_principal_binding: "local-user".to_owned(),
                allowed_capabilities: vec!["interactive-user-broker".to_owned()],
                allowed_effects: vec!["REVERSIBLE_MUTATION".to_owned()],
                config_snapshot: snapshot,
                heartbeat_ms: 1_000,
                control_channel: KERNEL_FRONT_DOOR_PIPE.to_owned(),
                rejection_reason: None,
                authority_epoch: AuthorityEpoch::new(7).expect("epoch"),
            }
        }

        #[test]
        fn server_hello_fixture_binds_numeric_generation_authority_and_artifact() {
            let artifact_digest = "a".repeat(64);
            let hello = server_hello(serde_json::json!({
                "service": KERNEL_SERVICE_NAME,
                "protocol": KERNEL_PROTOCOL_VERSION,
                "generation": 11,
                "authority_epoch": 7,
                "artifact_digest": artifact_digest,
            }));
            assert_eq!(
                validate_server_snapshot(&hello, 7, 11, &"a".repeat(64)),
                Ok(())
            );
        }

        #[test]
        fn server_hello_fixture_rejects_numeric_or_artifact_substitution() {
            let hello = server_hello(serde_json::json!({
                "service": KERNEL_SERVICE_NAME,
                "protocol": KERNEL_PROTOCOL_VERSION,
                "generation": 11,
                "authority_epoch": 7,
                "artifact_digest": "a".repeat(64),
            }));
            assert!(validate_server_snapshot(&hello, 7, 12, &"a".repeat(64)).is_err());
            assert!(validate_server_snapshot(&hello, 7, 11, &"b".repeat(64)).is_err());
        }

        #[test]
        fn server_hello_fixture_rejects_current_open_kernel_snapshot_until_n4_binds_artifact() {
            let hello = server_hello(serde_json::json!({
                "service": KERNEL_SERVICE_NAME,
                "protocol": KERNEL_PROTOCOL_VERSION,
                "generation": 1,
            }));
            assert!(validate_server_snapshot(&hello, 1, 1, &"a".repeat(64)).is_err());
        }
    }

    #[cfg(windows)]
    fn require_delivery(
        result: Result<DeliveryOutcome, eliot_ipc::TransportError>,
        operation: &str,
    ) -> Result<(), KernelClientError> {
        match result {
            Ok(DeliveryOutcome::Delivered) => Ok(()),
            Ok(DeliveryOutcome::UnknownOutcome) => Err(KernelClientError::UnknownOutcome(format!(
                "{operation} delivery outcome is unknown"
            ))),
            Err(error) => Err(KernelClientError::UnknownOutcome(format!(
                "{operation}: {error}"
            ))),
        }
    }
}

/// One generated command row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CommandSpec {
    pub id: CommandId,
    pub usage: &'static str,
    pub summary: &'static str,
    pub owner: &'static str,
    pub required_work_id: &'static str,
    pub argument_kind: ArgumentKind,
    pub effect: EffectClass,
    pub proof_ceiling: ProofCeiling,
    pub availability: CommandAvailability,
}

/// Argument shape name emitted with each generated command row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentKind {
    Empty,
    Snapshot,
    WorkUnit,
    Objective,
    Profile,
    ProfileScope,
    Module,
    ModuleAgainst,
    Edge,
    Artifact,
    ModuleScope,
    ModuleGeneration,
}

/// Generated availability metadata; it is never inferred from a runtime probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum CommandAvailability {
    Admitted,
    PlanGap {
        missing_work_id: &'static str,
        dependency: &'static str,
    },
    Unsupported {
        dependency: &'static str,
        detail: &'static str,
    },
    Unimplemented {
        architecture_anchor: &'static str,
        work_item_id: &'static str,
        detail: &'static str,
    },
}

/// Direct C0 provider identity with the actual provider contract shape digest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderContract {
    pub work_id: String,
    pub package: String,
    pub contract_name: String,
    pub contract_version: String,
    pub shape_sha256: String,
}

static COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        id: CommandId::SystemSnapshot,
        usage: "eliot system snapshot --repo-root <ABSOLUTE> --output <ABSOLUTE>",
        summary: "capture a current-system evidence snapshot",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Snapshot,
        effect: EffectClass::Read,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::Admitted,
    },
    CommandSpec {
        id: CommandId::BootstrapBrief,
        usage: "eliot bootstrap brief --work-unit <ABSOLUTE> --repo-root <ABSOLUTE>",
        summary: "compile a route-bounded brief and coverage manifest",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::WorkUnit,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::Admitted,
    },
    CommandSpec {
        id: CommandId::RecoveryStatus,
        usage: "eliot recovery status",
        summary: "inspect authenticated RecoveryView/fallback state",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Read,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::Ui,
        usage: "eliot ui",
        summary: "start or attach the authenticated User Broker UI",
        owner: "eliot-cli",
        required_work_id: "A-08",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::ExternalEffect,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-08",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::Dashboard,
        usage: "eliot dashboard",
        summary: "open the role-filtered terminal dashboard",
        owner: "eliot-cli",
        required_work_id: "A-08",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Read,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-08",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::DevImpactChanged,
        usage: "eliot dev impact --changed",
        summary: "build affected dependency/test/canary plan",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::DevCheckChanged,
        usage: "eliot dev check --changed",
        summary: "run T0 checks for changed crates/modules",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::DevTestChanged,
        usage: "eliot dev test --changed",
        summary: "execute selected module/edge/scenario profiles",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::DevPulse,
        usage: "eliot dev pulse --objective <objective-id>",
        summary: "run the smallest admitted Product pulse",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Objective,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::InstrumentRun,
        usage: "eliot instrument run --profile <profile> [--scope <scope>]",
        summary: "submit a durable instrument profile job",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::ProfileScope,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::ModuleValidate,
        usage: "eliot module validate <module-id>",
        summary: "validate ownership, direction and selectors",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Module,
        effect: EffectClass::Read,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::ModuleTest,
        usage: "eliot module test <module-id>",
        summary: "execute the generated ModuleTestCapsule",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Module,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::ModuleContractTest,
        usage: "eliot module contract-test <module-id> --against <revision>",
        summary: "run provider/consumer compatibility fixtures",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::ModuleAgainst,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::ModuleEdgeTest,
        usage: "eliot module edge-test <edge-id>",
        summary: "exercise the declared process/store/protocol edge",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Edge,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::ModuleBuild,
        usage: "eliot module build <module-id>",
        summary: "build an immutable module artifact and manifest",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Module,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::ModuleStage,
        usage: "eliot module stage <artifact>",
        summary: "verify and register a candidate generation",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Artifact,
        effect: EffectClass::ReversibleMutation,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::ModuleCanary,
        usage: "eliot module canary <module-id> --scope <scope>",
        summary: "start bounded candidate traffic",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::ModuleScope,
        effect: EffectClass::ReversibleMutation,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::ModulePromote,
        usage: "eliot module promote <module-id> <generation>",
        summary: "quiesce, switch, fence and drain a generation",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::ModuleGeneration,
        effect: EffectClass::ExternalEffect,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::ModuleRollback,
        usage: "eliot module rollback <module-id>",
        summary: "return to a compatible retained generation",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Module,
        effect: EffectClass::ReversibleMutation,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::ReleaseVerify,
        usage: "eliot release verify",
        summary: "run the T4 release gate",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Read,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::DoctorIntegration,
        usage: "eliot doctor integration <profile>",
        summary: "verify plugin, hook, protocol and runtime coverage",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Profile,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::BackupCreate,
        usage: "eliot backup create",
        summary: "manage a recovery artifact creation request",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::ReversibleMutation,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::BackupVerify,
        usage: "eliot backup verify",
        summary: "verify a recovery artifact",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::BackupRestoreTest,
        usage: "eliot backup restore-test",
        summary: "run an isolated restore test",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
    CommandSpec {
        id: CommandId::MaintenanceRun,
        usage: "eliot maintenance run",
        summary: "execute an admitted maintenance job and stop",
        owner: "eliot-cli",
        required_work_id: "A-06",
        argument_kind: ArgumentKind::Empty,
        effect: EffectClass::ReversibleMutation,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        availability: CommandAvailability::PlanGap {
            missing_work_id: "A-06",
            dependency: "no admitted Kernel/Governor provider is injected",
        },
    },
];

/// Errors from catalogue generation or pure client validation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CliError {
    #[error("catalogue: {0}")]
    Catalogue(#[from] CatalogueError),
    #[error("command port: {0}")]
    Port(#[from] CommandPortError),
    #[error("protocol request identity is invalid: {0}")]
    Protocol(String),
    #[error("unknown command: {0}")]
    UnknownCommand(String),
    #[error("argument field {field} is blank or contains control characters")]
    InvalidArgument { field: &'static str },
    #[error("command and typed arguments do not match")]
    ArgumentCommandMismatch,
    #[error("request and response correlation does not match")]
    CorrelationMismatch,
    #[error("result does not match the generated command availability")]
    ResultMismatch,
}

/// Errors proving that generated catalogue data is not canonical.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CatalogueError {
    #[error("catalogue must not be empty")]
    Empty,
    #[error("duplicate command: {0}")]
    DuplicateCommand(String),
    #[error("commands are not in canonical order: {previous} before {current}")]
    NonCanonicalOrder { previous: String, current: String },
    #[error("command {command} has a blank generated field: {field}")]
    BlankField {
        command: String,
        field: &'static str,
    },
    #[error("command {0} exceeds the candidate-only proof ceiling")]
    ProofCeiling(String),
    #[error("provider work id is duplicated: {0}")]
    DuplicateProvider(String),
    #[error("provider identity is incomplete: {0}")]
    InvalidProvider(String),
    #[error("provider identity failed: {0}")]
    ProviderIdentity(String),
    #[error("generated schema serialization failed: {0}")]
    Serialization(String),
}

/// The one immutable generated catalogue used by help, schema and execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandCatalogue;

impl CommandCatalogue {
    /// Returns the A-11 plan-v2 catalogue.
    pub const fn current() -> Self {
        Self
    }

    /// Returns all generated command rows in authority order.
    pub const fn commands(self) -> &'static [CommandSpec] {
        COMMANDS
    }

    /// Resolves actual provider contract identities from their owning crates.
    pub fn providers(self) -> Result<Vec<ProviderContract>, CatalogueError> {
        provider_contracts()
    }

    /// Validates catalogue uniqueness, order, provider identities and ceilings.
    pub fn validate(self) -> Result<(), CatalogueError> {
        let providers = self.providers()?;
        validate_catalogue(self.commands(), &providers)
    }

    fn find(self, command: CommandId) -> Result<&'static CommandSpec, CliError> {
        self.commands()
            .iter()
            .find(|spec| spec.id == command)
            .ok_or_else(|| CliError::UnknownCommand(command.as_str().to_owned()))
    }

    /// Renders exact hierarchical help from the same rows used by execution.
    pub fn help_text(self) -> Result<String, CatalogueError> {
        self.validate()?;
        let mut output = format!("eliot command catalogue {CATALOGUE_REVISION}\n\nCOMMANDS\n");
        for spec in self.commands() {
            writeln!(
                output,
                "  {}  [{}] {}",
                spec.usage,
                availability_code(spec.availability),
                spec.summary
            )
            .map_err(|error| CatalogueError::Serialization(error.to_string()))?;
        }
        Ok(output)
    }

    /// Renders actual executable input/output schemas plus catalogue rows.
    pub fn schema_json(self) -> Result<String, CatalogueError> {
        self.validate()?;
        let input_schema = command_request_input_schema()?;
        let output_schema = serde_json::to_value(schemars::schema_for!(CommandResponse))
            .map_err(|error| CatalogueError::Serialization(error.to_string()))?;
        let schema = GeneratedSchema {
            schema: SCHEMA_VERSION,
            catalogue: CATALOGUE_NAME,
            revision: CATALOGUE_REVISION,
            input_schema,
            output_schema,
            commands: self.commands().iter().map(schema_command).collect(),
            providers: self.providers()?,
        };
        serde_json::to_string(&schema)
            .map_err(|error| CatalogueError::Serialization(error.to_string()))
    }

    /// Validates and executes one operation without transport or external effects.
    pub fn execute(self, request: &CommandRequest) -> Result<CommandResponse, CliError> {
        self.validate()?;
        request.validate()?;
        let spec = self.find(request.command)?;
        let result = match spec.availability {
            CommandAvailability::Admitted => return Err(CliError::ResultMismatch),
            CommandAvailability::PlanGap {
                missing_work_id,
                dependency,
            } => CommandResult::Unavailable {
                reason: UnavailableReason::PlanGap {
                    missing_work_id: missing_work_id.to_owned(),
                    dependency: dependency.to_owned(),
                },
            },
            CommandAvailability::Unsupported { dependency, detail } => CommandResult::Unavailable {
                reason: UnavailableReason::Unsupported {
                    dependency: dependency.to_owned(),
                    detail: detail.to_owned(),
                },
            },
            CommandAvailability::Unimplemented {
                architecture_anchor,
                work_item_id,
                detail,
            } => CommandResult::Unimplemented {
                architecture_anchor: architecture_anchor.to_owned(),
                work_item_id: work_item_id.to_owned(),
                detail: detail.to_owned(),
            },
        };
        let response = CommandResponse {
            request: request.request.clone(),
            command: request.command,
            effect: spec.effect,
            proof_ceiling: spec.proof_ceiling,
            result,
        };
        response.validate_for(self, request)?;
        Ok(response)
    }

    /// Binds a locally captured artifact to the admitted snapshot command.
    ///
    /// The capture itself belongs to the short-lived `eliot` execution owner;
    /// this method only performs the public request/response correlation and
    /// availability proof.
    pub fn forwarded_snapshot_response(
        self,
        request: &CommandRequest,
        payload: Value,
    ) -> Result<CommandResponse, CliError> {
        self.validate()?;
        request.validate()?;
        if request.command != CommandId::SystemSnapshot {
            return Err(CliError::ResultMismatch);
        }
        let spec = self.find(request.command)?;
        let response = CommandResponse {
            request: request.request.clone(),
            command: request.command,
            effect: spec.effect,
            proof_ceiling: spec.proof_ceiling,
            result: CommandResult::Forwarded { payload },
        };
        response.validate_for(self, request)?;
        Ok(response)
    }

    /// Binds a locally compiled bootstrap brief to the admitted bootstrap
    /// command. The typed result is deliberately distinct from a forwarded
    /// Kernel payload and carries no authority beyond candidate evidence.
    pub fn bootstrap_brief_response(
        self,
        request: &CommandRequest,
        brief: eliot_bootstrap::BootstrapBrief,
    ) -> Result<CommandResponse, CliError> {
        self.validate()?;
        request.validate()?;
        if request.command != CommandId::BootstrapBrief {
            return Err(CliError::ResultMismatch);
        }
        let spec = self.find(request.command)?;
        let response = CommandResponse {
            request: request.request.clone(),
            command: request.command,
            effect: spec.effect,
            proof_ceiling: spec.proof_ceiling,
            result: CommandResult::BootstrapBrief {
                brief: Box::new(brief),
            },
        };
        response.validate_for(self, request)?;
        Ok(response)
    }

    /// Validates and forwards one request through an injected Kernel port.
    ///
    /// This method is intentionally separate from [`Self::execute`]: the
    /// catalogue can describe unavailable rows, but the production client must
    /// never convert that metadata into local authority or a fake success.
    pub fn dispatch<P: CommandPort + ?Sized>(
        self,
        port: &mut P,
        request: &CommandRequest,
    ) -> Result<CommandResponse, CliError> {
        self.validate()?;
        request.validate()?;
        let response = port.dispatch(request).map_err(CliError::Port)?;
        response.validate_for(self, request)?;
        Ok(response)
    }
}

impl CommandResponse {
    /// Verifies complete `RequestIdentity`, command, effect, ceiling and result parity.
    pub fn validate_for(
        &self,
        catalogue: CommandCatalogue,
        request: &CommandRequest,
    ) -> Result<(), CliError> {
        request.validate()?;
        self.request
            .validate()
            .map_err(|error| CliError::Protocol(error.to_string()))?;
        if self.request != request.request || self.command != request.command {
            return Err(CliError::CorrelationMismatch);
        }
        let spec = catalogue.find(request.command)?;
        if self.effect != spec.effect || self.proof_ceiling != spec.proof_ceiling {
            return Err(CliError::ResultMismatch);
        }
        validate_result_for(spec.id, &spec.availability, &self.result)?;
        Ok(())
    }
}

fn validate_result_for(
    command: CommandId,
    availability: &CommandAvailability,
    result: &CommandResult,
) -> Result<(), CliError> {
    match (availability, result) {
        (CommandAvailability::Admitted, CommandResult::Forwarded { .. }) => {}
        (CommandAvailability::Admitted, CommandResult::BootstrapBrief { .. })
            if command == CommandId::BootstrapBrief => {}
        (
            CommandAvailability::PlanGap {
                missing_work_id,
                dependency,
            },
            CommandResult::Unavailable {
                reason:
                    UnavailableReason::PlanGap {
                        missing_work_id: actual,
                        dependency: actual_dependency,
                    },
            },
        ) if actual == missing_work_id && actual_dependency == dependency => {}
        (
            CommandAvailability::Unsupported { dependency, detail },
            CommandResult::Unavailable {
                reason:
                    UnavailableReason::Unsupported {
                        dependency: actual_dependency,
                        detail: actual_detail,
                    },
            },
        ) if actual_dependency == dependency && actual_detail == detail => {}
        (
            CommandAvailability::Unimplemented {
                architecture_anchor,
                work_item_id,
                detail,
            },
            CommandResult::Unimplemented {
                architecture_anchor: actual_architecture_anchor,
                work_item_id: actual_work_item_id,
                detail: actual_detail,
            },
        ) if actual_architecture_anchor == architecture_anchor
            && actual_work_item_id == work_item_id
            && actual_detail == detail => {}
        _ => return Err(CliError::ResultMismatch),
    }
    Ok(())
}

/// Validates an arbitrary generated catalogue fixture for duplicate/order negatives.
pub fn validate_catalogue(
    commands: &[CommandSpec],
    providers: &[ProviderContract],
) -> Result<(), CatalogueError> {
    if commands.is_empty() {
        return Err(CatalogueError::Empty);
    }
    let mut seen = BTreeSet::new();
    let mut previous: Option<CommandId> = None;
    for spec in commands {
        let id = spec.id.as_str();
        if !seen.insert(id) {
            return Err(CatalogueError::DuplicateCommand(id.to_owned()));
        }
        if let Some(previous) = previous
            && previous >= spec.id
        {
            return Err(CatalogueError::NonCanonicalOrder {
                previous: previous.as_str().to_owned(),
                current: id.to_owned(),
            });
        }
        previous = Some(spec.id);
        for (field, value) in [
            ("usage", spec.usage),
            ("summary", spec.summary),
            ("owner", spec.owner),
            ("required_work_id", spec.required_work_id),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(CatalogueError::BlankField {
                    command: id.to_owned(),
                    field,
                });
            }
        }
        if spec.proof_ceiling > ProofCeiling::CandidateArtifact {
            return Err(CatalogueError::ProofCeiling(id.to_owned()));
        }
        if spec.availability == CommandAvailability::Admitted
            && spec.required_work_id != "A-11"
            // A-06 owns the two one-shot D0 compilers. They execute locally
            // and do not acquire Kernel or MCP authority.
            && !matches!(
                spec.id,
                CommandId::SystemSnapshot | CommandId::BootstrapBrief
            )
        {
            return Err(CatalogueError::InvalidProvider(id.to_owned()));
        }
    }
    let mut provider_ids = BTreeSet::new();
    for provider in providers {
        if !provider_ids.insert(provider.work_id.as_str()) {
            return Err(CatalogueError::DuplicateProvider(provider.work_id.clone()));
        }
        if [
            provider.work_id.as_str(),
            provider.package.as_str(),
            provider.contract_name.as_str(),
            provider.contract_version.as_str(),
            provider.shape_sha256.as_str(),
        ]
        .iter()
        .any(|value| value.trim().is_empty())
        {
            return Err(CatalogueError::InvalidProvider(provider.work_id.clone()));
        }
    }
    Ok(())
}

fn provider_contracts() -> Result<Vec<ProviderContract>, CatalogueError> {
    let observations = eliot_observation_contracts::contract_identity()
        .map_err(|error| CatalogueError::ProviderIdentity(error.to_string()))?;
    let protocol = eliot_protocol::protocol_contract_identity()
        .map_err(|error| CatalogueError::ProviderIdentity(error.to_string()))?;
    let receipts = eliot_receipts::contract_identity()
        .map_err(|error| CatalogueError::ProviderIdentity(error.to_string()))?;
    let runtime = eliot_runtime_contracts::contract_identity()
        .map_err(|error| CatalogueError::ProviderIdentity(error.to_string()))?;
    Ok(vec![
        provider(
            "C0-02",
            "eliot-receipts",
            receipts.name.to_string(),
            receipts.version.to_string(),
            receipts.shape_sha256,
        ),
        provider(
            "C0-04",
            "eliot-runtime-contracts",
            runtime.name.to_string(),
            runtime.version.to_string(),
            runtime.shape_sha256,
        ),
        provider(
            "C0-07",
            "eliot-protocol",
            protocol.name.to_string(),
            protocol.version.to_string(),
            protocol.shape_sha256,
        ),
        provider(
            "C0-11",
            "eliot-observation-contracts",
            observations.name.to_string(),
            observations.version.to_string(),
            observations.shape_sha256,
        ),
    ])
}

fn provider(
    work_id: &str,
    package: &str,
    contract_name: String,
    contract_version: String,
    shape_sha256: String,
) -> ProviderContract {
    ProviderContract {
        work_id: work_id.to_owned(),
        package: package.to_owned(),
        contract_name,
        contract_version,
        shape_sha256,
    }
}

fn command_request_input_schema() -> Result<Value, CatalogueError> {
    let command_request_schema = serde_json::to_value(schemars::schema_for!(CommandRequest))
        .map_err(|error| CatalogueError::Serialization(error.to_string()))?;
    let request_schema = command_request_schema
        .pointer("/properties/request")
        .cloned()
        .ok_or_else(|| {
            CatalogueError::Serialization(
                "CommandRequest schema has no request property".to_owned(),
            )
        })?;
    let argument_schema = serde_json::to_value(schemars::schema_for!(CommandArguments))
        .map_err(|error| CatalogueError::Serialization(error.to_string()))?;
    let argument_variants = argument_schema
        .get("oneOf")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CatalogueError::Serialization(
                "CommandArguments schema has no oneOf variants".to_owned(),
            )
        })?;
    let one_of = COMMANDS
        .iter()
        .map(|spec| -> Result<Value, CatalogueError> {
            let command_tag = spec.id.as_str().replace('-', "_");
            let arguments = argument_variants
                .iter()
                .find(|variant| {
                    variant
                        .pointer("/properties/kind/const")
                        .and_then(Value::as_str)
                        == Some(command_tag.as_str())
                })
                .cloned()
                .ok_or_else(|| {
                    CatalogueError::Serialization(format!(
                        "CommandArguments schema has no variant for {command_tag}"
                    ))
                })?;
            Ok(json!({
                "type": "object",
                "properties": {
                    "request": request_schema.clone(),
                    "command": {
                        "type": "string",
                        "const": spec.id.as_str()
                    },
                    "arguments": arguments
                },
                "required": ["request", "command", "arguments"],
                "additionalProperties": false
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut schema = serde_json::Map::new();
    if let Some(schema_version) = command_request_schema.get("$schema") {
        schema.insert("$schema".to_owned(), schema_version.clone());
    }
    if let Some(definitions) = command_request_schema.get("$defs") {
        schema.insert("$defs".to_owned(), definitions.clone());
    }
    schema.insert(
        "title".to_owned(),
        Value::String("CommandRequest".to_owned()),
    );
    schema.insert("type".to_owned(), Value::String("object".to_owned()));
    schema.insert("oneOf".to_owned(), Value::Array(one_of));
    Ok(Value::Object(schema))
}

#[derive(Serialize)]
struct GeneratedSchema {
    schema: &'static str,
    catalogue: &'static str,
    revision: &'static str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    commands: Vec<SchemaCommand>,
    providers: Vec<ProviderContract>,
}

#[derive(Serialize)]
struct SchemaCommand {
    id: &'static str,
    usage: &'static str,
    summary: &'static str,
    owner: &'static str,
    required_work_id: &'static str,
    argument_kind: ArgumentKind,
    effect: EffectClass,
    proof_ceiling: ProofCeiling,
    availability: SchemaAvailability,
}

#[derive(Serialize)]
struct SchemaAvailability {
    code: &'static str,
    dependency: &'static str,
    missing_work_id: Option<&'static str>,
    architecture_anchor: Option<&'static str>,
    work_item_id: Option<&'static str>,
    detail: Option<&'static str>,
}

fn schema_command(spec: &CommandSpec) -> SchemaCommand {
    let availability = match spec.availability {
        CommandAvailability::Admitted => SchemaAvailability {
            code: "ADMITTED",
            dependency: "eliot-cli",
            missing_work_id: None,
            architecture_anchor: None,
            work_item_id: None,
            detail: None,
        },
        CommandAvailability::PlanGap {
            missing_work_id,
            dependency,
        } => SchemaAvailability {
            code: CONTROLBOARD_PLAN_GAP,
            dependency,
            missing_work_id: Some(missing_work_id),
            architecture_anchor: None,
            work_item_id: None,
            detail: None,
        },
        CommandAvailability::Unsupported { dependency, detail } => SchemaAvailability {
            code: "UNSUPPORTED",
            dependency,
            missing_work_id: None,
            architecture_anchor: None,
            work_item_id: None,
            detail: Some(detail),
        },
        CommandAvailability::Unimplemented {
            architecture_anchor,
            work_item_id,
            detail,
        } => SchemaAvailability {
            code: "UNIMPLEMENTED",
            dependency: "eliot-cli",
            missing_work_id: None,
            architecture_anchor: Some(architecture_anchor),
            work_item_id: Some(work_item_id),
            detail: Some(detail),
        },
    };
    SchemaCommand {
        id: spec.id.as_str(),
        usage: spec.usage,
        summary: spec.summary,
        owner: spec.owner,
        required_work_id: spec.required_work_id,
        argument_kind: spec.argument_kind,
        effect: spec.effect,
        proof_ceiling: spec.proof_ceiling,
        availability,
    }
}

const fn availability_code(availability: CommandAvailability) -> &'static str {
    match availability {
        CommandAvailability::Admitted => "ADMITTED",
        CommandAvailability::PlanGap { .. } => CONTROLBOARD_PLAN_GAP,
        CommandAvailability::Unsupported { .. } => "UNSUPPORTED",
        CommandAvailability::Unimplemented { .. } => "UNIMPLEMENTED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opening_fence(line: &str) -> Option<(char, usize)> {
        let trimmed = line.trim_start_matches([' ', '\t']);
        let marker = trimmed.chars().next()?;
        if !matches!(marker, '`' | '~') {
            return None;
        }
        let width = trimmed
            .chars()
            .take_while(|character| *character == marker)
            .count();
        (width >= 3).then_some((marker, width))
    }

    fn closes_fence(line: &str, marker: char, minimum_width: usize) -> bool {
        let trimmed = line.trim_matches(|character| character == ' ' || character == '\t');
        trimmed.chars().count() >= minimum_width
            && trimmed.chars().all(|character| character == marker)
    }

    fn normative_heading_exists(text: &str, anchor: &str) -> bool {
        let mut fence = None;
        let heading_prefix = format!("{anchor}.");
        for line in text.lines() {
            if let Some((marker, width)) = fence {
                if closes_fence(line, marker, width) {
                    fence = None;
                }
                continue;
            }
            if let Some(opening) = opening_fence(line) {
                fence = Some(opening);
                continue;
            }

            let trimmed = line.trim_start_matches([' ', '\t']);
            let hashes = trimmed
                .chars()
                .take_while(|character| *character == '#')
                .count();
            if !(1..=6).contains(&hashes) {
                continue;
            }
            let heading = trimmed[hashes..].trim_start_matches([' ', '\t']);
            if heading
                .strip_prefix(&heading_prefix)
                .is_some_and(|remainder| remainder.starts_with(' ') || remainder.starts_with('\t'))
            {
                return true;
            }
        }
        false
    }

    #[test]
    fn normative_heading_scanner_ignores_info_string_fences() {
        let fixture = "```text\n## A9.9. fenced example\n```\n## A0.8. real heading\n";
        assert!(!normative_heading_exists(fixture, "A9.9"));
        assert!(normative_heading_exists(fixture, "A0.8"));
    }

    #[test]
    fn provider_identity_comes_from_actual_contract_shapes() -> Result<(), CatalogueError> {
        assert_eq!(MCP_SURFACE_CONTRACT_REVISION, "1.0.0");
        let providers = CommandCatalogue::current().providers()?;
        assert_eq!(providers.len(), 4);
        assert!(
            providers
                .iter()
                .all(|provider| !provider.contract_version.trim().is_empty())
        );
        assert!(
            providers
                .iter()
                .all(|provider| provider.shape_sha256.len() == 64)
        );
        Ok(())
    }

    #[test]
    fn controlboard_plan_gap_marker_is_pinned() {
        assert_eq!(CONTROLBOARD_PLAN_GAP, "PLAN_GAP");
    }

    #[test]
    fn unimplemented_result_requires_exact_field_correlation() {
        let availability = CommandAvailability::Unimplemented {
            architecture_anchor: "A0.8",
            work_item_id: "W0-01",
            detail: "implementation is intentionally bounded to a later work item",
        };
        let result = CommandResult::Unimplemented {
            architecture_anchor: "A0.8".to_owned(),
            work_item_id: "W0-01".to_owned(),
            detail: "implementation is intentionally bounded to a later work item".to_owned(),
        };
        assert!(validate_result_for(CommandId::BootstrapBrief, &availability, &result).is_ok());

        for result in [
            CommandResult::Unimplemented {
                architecture_anchor: "A0.9".to_owned(),
                work_item_id: "W0-01".to_owned(),
                detail: "implementation is intentionally bounded to a later work item".to_owned(),
            },
            CommandResult::Unimplemented {
                architecture_anchor: "A0.8".to_owned(),
                work_item_id: "W0-02".to_owned(),
                detail: "implementation is intentionally bounded to a later work item".to_owned(),
            },
            CommandResult::Unimplemented {
                architecture_anchor: "A0.8".to_owned(),
                work_item_id: "W0-01".to_owned(),
                detail: "different detail".to_owned(),
            },
        ] {
            assert_eq!(
                validate_result_for(CommandId::BootstrapBrief, &availability, &result),
                Err(CliError::ResultMismatch)
            );
        }
        assert_eq!(
            validate_result_for(
                CommandId::BootstrapBrief,
                &availability,
                &CommandResult::Unavailable {
                    reason: UnavailableReason::PlanGap {
                        missing_work_id: "W0-01".to_owned(),
                        dependency: "eliot-cli".to_owned(),
                    },
                },
            ),
            Err(CliError::ResultMismatch)
        );
    }

    #[test]
    fn typed_unimplemented_anchors_resolve_to_normative_headings()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let architecture =
            std::fs::read_to_string(repository_root.join("docs/normative/ELIOT_ARCHITECTURE.md"))?;
        let implementation = std::fs::read_to_string(
            repository_root.join("docs/normative/ELIOT_IMPLEMENTATION.md"),
        )?;
        let normative_pair = format!("{architecture}\n{implementation}");
        let mut checked = 0_usize;

        for spec in CommandCatalogue::current().commands() {
            if let CommandAvailability::Unimplemented {
                architecture_anchor,
                ..
            } = spec.availability
            {
                assert!(
                    normative_heading_exists(&normative_pair, architecture_anchor),
                    "catalogue Unimplemented anchor {architecture_anchor} is not a normative heading"
                );
                checked += 1;
            }
        }

        for result in [CommandResult::Unimplemented {
            architecture_anchor: "A0.8".to_owned(),
            work_item_id: "W0-01".to_owned(),
            detail: "typed oracle fixture".to_owned(),
        }] {
            if let CommandResult::Unimplemented {
                architecture_anchor,
                ..
            } = result
            {
                assert!(
                    normative_heading_exists(&normative_pair, &architecture_anchor),
                    "result Unimplemented anchor {architecture_anchor} is not a normative heading"
                );
                checked += 1;
            }
        }

        assert_ne!(checked, 0, "typed anchor oracle did not examine any values");
        Ok(())
    }
}
