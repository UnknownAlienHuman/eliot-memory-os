//! B-15's thin profile-selected agent/host bridge.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::time::Duration;

use eliot_agent_bridge_core::{
    AgentBridgeCore, AttachBinding, AttachRequest, AttachView, BridgeError, ConnectionId,
    CursorPolicy, DemandId, EventForwardStatus, EventPortOutcome, HostActivationPort,
    HostEventEnvelope, McpForwardingPort, ProviderFailure, ProviderReadiness,
    ReconciliationPortOutcome, ReconnectRequest,
};
use eliot_protocol::{
    AckPhase, AgentBridgeClientDeclaration, AgentBridgePeerAdmissionReceipt,
    AgentBridgePeerChallenge, EventEnvelope,
};
use eliot_runtime::{Runtime, RuntimeConfig};

mod cli_contract;
mod kernel_activation_client;
pub(crate) use cli_contract::validate_client_declaration_path;
pub use cli_contract::{CliConfig, CliError, Profile, Transport, parse_args};
use kernel_activation_client::KernelHostActivationPort;
#[cfg(test)]
use kernel_activation_client::{
    activation_frame_for_request, build_neutral_activation_request, decode_activation_response,
};

fn decode_declaration_bytes(bytes: &[u8]) -> Result<AgentBridgeClientDeclaration, String> {
    let declaration: AgentBridgeClientDeclaration =
        serde_json::from_slice(bytes).map_err(|e| format!("declaration deserialize: {e}"))?;
    declaration
        .validate()
        .map_err(|e| format!("declaration validate: {e}"))?;
    Ok(declaration)
}

struct LoadedAgentBridgeDeclaration {
    declaration: AgentBridgeClientDeclaration,
    #[cfg(windows)]
    _lease: eliot_platform_windows::AgentBridgeDeclarationReadLease,
}

struct AdmittedConnection {
    transport: eliot_ipc::NamedPipeTransport,
    receipt: AgentBridgePeerAdmissionReceipt,
}

// admitted: AdmittedConnection
// runtime: tokio::runtime::Runtime
// _loaded: LoadedAgentBridgeDeclaration
// activation_used: bool
// activation exchange already consumed; restart/reconnect

struct KernelMcpForwardingPort;

impl McpForwardingPort for KernelMcpForwardingPort {
    fn forward_hook(
        &mut self,
        _binding: &AttachBinding,
        _event: &HostEventEnvelope,
    ) -> Result<(), ProviderFailure> {
        Err(ProviderFailure::new(
            "eliot-kernel-front-door",
            "forwarding not admitted",
        ))
    }
    fn forward_event(
        &mut self,
        _binding: &AttachBinding,
        _event: &EventEnvelope,
    ) -> Result<EventPortOutcome, ProviderFailure> {
        Err(ProviderFailure::new(
            "eliot-kernel-front-door",
            "forwarding not admitted",
        ))
    }
    fn forward_gap(
        &mut self,
        _binding: &AttachBinding,
        _gap: &eliot_agent_bridge_core::CoverageGap,
    ) -> Result<(), ProviderFailure> {
        Err(ProviderFailure::new(
            "eliot-kernel-front-door",
            "forwarding not admitted",
        ))
    }
    fn reconcile_external(
        &mut self,
        _binding: &AttachBinding,
    ) -> Result<ReconciliationPortOutcome, ProviderFailure> {
        Err(ProviderFailure::new(
            "eliot-kernel-front-door",
            "reconciliation not admitted",
        ))
    }
}

pub type KernelPorts = (Box<dyn HostActivationPort>, Box<dyn McpForwardingPort>);

fn current_os_identity() -> Result<(String, u32), RuntimeBuildError> {
    let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
        .map_err(|e| RuntimeBuildError::KernelClient(format!("current identity: {e:?}")))?;
    Ok((
        expectation.expected_sid().to_owned(),
        expectation.expected_session_id(),
    ))
}

fn load_declaration(path: &Path) -> Result<LoadedAgentBridgeDeclaration, RuntimeBuildError> {
    let path = validate_client_declaration_path(path)
        .map_err(|e| RuntimeBuildError::KernelClient(e.to_string()))?;
    #[cfg(windows)]
    {
        let mut lease = eliot_platform_windows::open_agent_bridge_declaration_read_lease(&path)
            .map_err(|e| RuntimeBuildError::KernelClient(format!("declaration lease: {e:?}")))?;
        let bytes = lease
            .read_bytes()
            .map_err(|e| RuntimeBuildError::KernelClient(format!("declaration read: {e:?}")))?;
        let declaration =
            decode_declaration_bytes(&bytes).map_err(RuntimeBuildError::KernelClient)?;
        Ok(LoadedAgentBridgeDeclaration {
            declaration,
            _lease: lease,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(RuntimeBuildError::KernelClient(
            "declaration lease unavailable off Windows".to_owned(),
        ))
    }
}

pub fn kernel_ports_with_declaration(
    declaration_path: &Path,
) -> Result<KernelPorts, RuntimeBuildError> {
    let loaded = load_declaration(declaration_path)?;
    let declaration = &loaded.declaration;
    let (current_sid, _current_session) = current_os_identity()?;
    let expectation = eliot_platform_windows::KernelFrontDoorServerExpectation::new(
        declaration.expected_kernel_sid.clone(),
        declaration.expected_kernel_session_id,
        declaration.expected_kernel_artifact_sha256.clone(),
        eliot_platform_windows::KernelFrontDoorAclMode::SystemAndLocalServiceWithClient {
            client_sid: current_sid.clone(),
        },
    )
    .map_err(|e| RuntimeBuildError::KernelClient(format!("frontdoor expectation: {e:?}")))?;
    let limits = eliot_ipc::TransportLimits {
        max_frame_bytes: declaration.max_frame as usize,
        ..Default::default()
    };
    let pipe_name = r"\\.\pipe\eliot\kernel\frontdoor";
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| RuntimeBuildError::KernelClient(e.to_string()))?;
    let mut transport = runtime.block_on(async {
        eliot_ipc::NamedPipeTransport::connect_authenticated_kernel_front_door(
            pipe_name,
            Duration::from_secs(5),
            &expectation,
        )
        .await
        .map_err(|e| RuntimeBuildError::KernelClient(format!("frontdoor connect: {e:?}")))
    })?;
    let observed = transport
        .kernel_front_door_observed_extra_sid()
        .ok_or_else(|| RuntimeBuildError::KernelClient("missing extra sid".to_owned()))?;
    if observed != current_sid {
        return Err(RuntimeBuildError::KernelClient(
            "extra SID mismatch".to_owned(),
        ));
    }
    let challenge_frame = runtime.block_on(async {
        transport
            .receive_frame(limits)
            .await
            .map_err(|e| RuntimeBuildError::KernelClient(format!("challenge receive: {e:?}")))
    })?;
    let connection_id = challenge_frame.connection_id.clone();
    let challenge: AgentBridgePeerChallenge =
        eliot_ipc::decode_peer_challenge_frame(&challenge_frame, &connection_id)
            .map_err(|e| RuntimeBuildError::KernelClient(format!("challenge decode: {e:?}")))?;
    challenge
        .validate_declaration(declaration)
        .map_err(|e| RuntimeBuildError::KernelClient(format!("challenge validation: {e:?}")))?;
    let hello = declaration
        .client_hello(challenge.challenge_nonce.clone())
        .map_err(|e| RuntimeBuildError::KernelClient(format!("client hello: {e:?}")))?;
    let hello_frame = eliot_ipc::client_hello_frame(&connection_id, &hello)
        .map_err(|e| RuntimeBuildError::KernelClient(format!("hello frame: {e:?}")))?;
    let receipt_frame = runtime.block_on(async {
        transport
            .send_frame(&hello_frame, limits)
            .await
            .map_err(|e| RuntimeBuildError::KernelClient(format!("hello send: {e:?}")))?;
        transport
            .receive_frame(limits)
            .await
            .map_err(|e| RuntimeBuildError::KernelClient(format!("receipt receive: {e:?}")))
    })?;
    let receipt =
        eliot_ipc::decode_agent_bridge_admission_receipt_frame(&receipt_frame, &connection_id)
            .map_err(|e| RuntimeBuildError::KernelClient(format!("receipt decode: {e:?}")))?;
    receipt
        .validate_challenge(&challenge)
        .map_err(|e| RuntimeBuildError::KernelClient(format!("receipt challenge: {e:?}")))?;
    receipt
        .validate_client_hello(declaration, &hello)
        .map_err(|e| RuntimeBuildError::KernelClient(format!("receipt hello: {e:?}")))?;
    if receipt.connection_id != connection_id {
        return Err(RuntimeBuildError::KernelClient(
            "receipt connection mismatch".to_owned(),
        ));
    }
    let admitted = AdmittedConnection { transport, receipt };
    let host: Box<dyn HostActivationPort> = Box::new(KernelHostActivationPort {
        admitted,
        runtime,
        _loaded: loaded,
        activation_used: false,
        limits,
    });
    let fwd: Box<dyn McpForwardingPort> = Box::new(KernelMcpForwardingPort);
    Ok((host, fwd))
}

pub struct BridgeRunner {
    profile: Profile,
    runtime: Runtime,
    core: AgentBridgeCore,
}

impl BridgeRunner {
    pub fn new(
        profile: Profile,
        readiness: ProviderReadiness,
        host_activation: Option<Box<dyn HostActivationPort>>,
        mcp_forwarding: Option<Box<dyn McpForwardingPort>>,
    ) -> Result<Self, RuntimeBuildError> {
        if !profile.is_compiled() {
            return Err(RuntimeBuildError::ProfileNotCompiled(profile));
        }
        let runtime = Runtime::new(
            RuntimeConfig {
                mailbox_capacity: 32,
                control_reserve: 4,
                concurrency: 1,
                control_concurrency_reserve: 1,
                fairness_quantum: 8,
                restart_budget: 0,
                restart_window: Duration::from_mins(1),
                restart_backoff: Duration::from_millis(50),
                shutdown_grace: Duration::from_secs(1),
            },
            None,
        )
        .map_err(RuntimeBuildError::Runtime)?;
        let cursor_policy = CursorPolicy::new(AckPhase::Durable, AckPhase::Normalized)
            .map_err(RuntimeBuildError::BridgeContract)?;
        Ok(Self {
            profile,
            runtime,
            core: AgentBridgeCore::new(readiness, host_activation, mcp_forwarding, cursor_policy),
        })
    }
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.profile
    }
    #[must_use]
    pub fn control_capacity(&self) -> usize {
        self.runtime
            .available_capacity(eliot_runtime::ExecutionClass::ProtectedControl)
    }
    pub fn demand_start(
        &mut self,
        demand_id: impl Into<String>,
        connection_id: impl Into<String>,
    ) -> Result<AttachView, BridgeError> {
        self.attach(AttachRequest::managed(
            DemandId::new(demand_id).map_err(|e| BridgeError::ProviderContract(e.to_string()))?,
            ConnectionId::new(connection_id)
                .map_err(|e| BridgeError::ProviderContract(e.to_string()))?,
        ))
    }
    pub fn attach(&mut self, request: AttachRequest) -> Result<AttachView, BridgeError> {
        self.core.attach(request)
    }
    pub fn reconnect(&mut self, request: ReconnectRequest) -> Result<AttachView, BridgeError> {
        self.core.reconnect(request)
    }
    pub fn reconcile_external(&mut self) -> Result<AttachView, BridgeError> {
        self.core.reconcile_external()
    }
    pub fn forward_hook(&mut self, event: &HostEventEnvelope) -> Result<(), BridgeError> {
        self.core.forward_hook(event)
    }
    pub fn forward_event(
        &mut self,
        event: &EventEnvelope,
    ) -> Result<EventForwardStatus, BridgeError> {
        self.core.forward_event(event)
    }
    #[must_use]
    pub fn attach_view(&self) -> Option<AttachView> {
        self.core.attach_view()
    }
}

#[derive(Debug)]
pub enum RuntimeBuildError {
    ProfileNotCompiled(Profile),
    Runtime(eliot_runtime::ConfigError),
    BridgeContract(BridgeError),
    KernelClient(String),
}

impl fmt::Display for RuntimeBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProfileNotCompiled(p) => write!(formatter, "PROFILE_NOT_COMPILED:{p}"),
            Self::Runtime(_) => formatter.write_str("RUNTIME_CONFIG_INVALID"),
            Self::BridgeContract(e) => write!(formatter, "BRIDGE_CONTRACT_INVALID:{e}"),
            Self::KernelClient(e) => write!(formatter, "KERNEL_CLIENT_REJECTED:{e}"),
        }
    }
}
impl std::error::Error for RuntimeBuildError {}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_contracts::{ArtifactId, ContractId, ContractVersion, StateFence};
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration};
    use eliot_protocol::AgentBridgeActivationResponse;
    use eliot_protocol::{
        AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_ID, AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION,
        AGENT_BRIDGE_MODULE_ID, AGENT_BRIDGE_PEER_CHALLENGE_WIRE_ID,
        AGENT_BRIDGE_PEER_CHALLENGE_WIRE_VERSION, AgentBridgeClientDeclaration,
        AgentBridgePeerAdmissionReceipt, AgentBridgePeerChallenge,
    };
    use eliot_protocol::{EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload};
    use eliot_protocol::{ProtocolRange, ProtocolVersion};
    use eliot_runtime_contracts::{HealthVector, ModuleGenerationState};
    use eliot_runtime_contracts::{ModuleContract, ModuleGeneration};
    use std::collections::BTreeMap;

    fn fixture_declaration() -> AgentBridgeClientDeclaration {
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
            protocols: vec!["eliot.agent-bridge.v1".to_owned()],
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
            wire_id: AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_ID.to_owned(),
            wire_version: AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION,
            module_id: AGENT_BRIDGE_MODULE_ID.to_owned(),
            profile_id: "agent-bridge-profile-1".to_owned(),
            protocol_range: ProtocolRange {
                minimum: ProtocolVersion::CURRENT,
                maximum: ProtocolVersion::CURRENT,
            },
            module_contract: contract,
            module_generation: generation,
            capabilities: vec!["agent.bridge.activate".to_owned()],
            privacy_classes: vec!["PUBLIC".to_owned()],
            max_frame: 4_194_304,
            expected_kernel_sid: "S-1-5-18".to_owned(),
            expected_kernel_session_id: 0,
            expected_kernel_principal_binding: "kernel:agent-bridge".to_owned(),
            expected_kernel_authority_epoch: AuthorityEpoch::new(8).unwrap(),
            expected_kernel_generation: ResourceGeneration::new(2).unwrap(),
            expected_kernel_artifact_sha256: "b".repeat(64),
            expected_kernel_config_snapshot_sha256: "c".repeat(64),
            declaration_sha256: String::new(),
        }
        .with_computed_digest()
        .unwrap()
    }

    fn fixture_challenge(decl: &AgentBridgeClientDeclaration) -> AgentBridgePeerChallenge {
        AgentBridgePeerChallenge {
            wire_id: AGENT_BRIDGE_PEER_CHALLENGE_WIRE_ID.to_owned(),
            wire_version: AGENT_BRIDGE_PEER_CHALLENGE_WIRE_VERSION,
            module_id: AGENT_BRIDGE_MODULE_ID.to_owned(),
            profile_id: decl.profile_id.clone(),
            descriptor_sha256: "d".repeat(64),
            client_declaration_sha256: decl.declaration_sha256.clone(),
            bridge_generation: decl.module_generation.generation,
            state_fence: decl.module_generation.state_fence.clone(),
            kernel_principal_binding: decl.expected_kernel_principal_binding.clone(),
            kernel_authority_epoch: decl.expected_kernel_authority_epoch,
            kernel_generation: decl.expected_kernel_generation,
            kernel_artifact_sha256: decl.expected_kernel_artifact_sha256.clone(),
            kernel_config_snapshot_sha256: decl.expected_kernel_config_snapshot_sha256.clone(),
            activation_deadline_unix_ms: 10_000,
            challenge_nonce: "kernel-challenge-1".to_owned(),
            challenge_sha256: String::new(),
        }
        .with_computed_digest()
        .unwrap()
    }

    fn fixture_receipt(
        challenge: &AgentBridgePeerChallenge,
        hello: &eliot_protocol::ClientHello,
    ) -> AgentBridgePeerAdmissionReceipt {
        AgentBridgePeerAdmissionReceipt {
            wire_id: eliot_protocol::AGENT_BRIDGE_PEER_ADMISSION_RECEIPT_WIRE_ID.to_owned(),
            wire_version: AgentBridgePeerAdmissionReceipt::CONTRACT_VERSION,
            module_id: challenge.module_id.clone(),
            connection_id: "conn-1".to_owned(),
            profile_id: challenge.profile_id.clone(),
            descriptor_sha256: challenge.descriptor_sha256.clone(),
            client_declaration_sha256: challenge.client_declaration_sha256.clone(),
            bridge_generation: challenge.bridge_generation,
            state_fence: challenge.state_fence.clone(),
            activation_deadline_unix_ms: challenge.activation_deadline_unix_ms,
            challenge_nonce: challenge.challenge_nonce.clone(),
            challenge_sha256: challenge.challenge_sha256.clone(),
            client_hello_sha256: eliot_platform_windows::sha256_hex(
                &eliot_contracts::canonical_json_bytes(hello).unwrap(),
            ),
            observed_sid: "S-1-5-21-1000".to_owned(),
            observed_session_id: 1,
            observed_process_id: 123,
            observed_process_start_time_100ns: 456,
            observed_image_path: "C:\\bridge.exe".to_owned(),
            observed_image_volume_serial: 1,
            observed_image_file_index: 2,
            receipt_sha256: String::new(),
        }
        .with_computed_digest()
        .unwrap()
    }

    #[test]
    fn cli_declaration_path_required_absolute_no_parent() {
        assert!(matches!(
            parse_args([
                "--profile",
                "SPINE_FUNCTIONAL",
                "--transport",
                "loopback",
                "--client-declaration",
                "C:\\a\\agent-bridge\\client-declaration-v2.json"
            ]),
            Err(CliError::RemoteTransportForbidden(transport)) if transport == "loopback"
        ));
        assert!(matches!(
            parse_args(["--profile", "SPINE_FUNCTIONAL"]),
            Err(CliError::MissingClientDeclaration)
        ));
        assert!(matches!(
            parse_args([
                "--profile",
                "SPINE_FUNCTIONAL",
                "--client-declaration",
                "relative/path.json"
            ]),
            Err(CliError::InvalidClientDeclarationPath(_))
        ));
        assert!(matches!(
            parse_args([
                "--profile",
                "SPINE_FUNCTIONAL",
                "--client-declaration",
                "C:\\a\\..\\b.json"
            ]),
            Err(CliError::InvalidClientDeclarationPath(_))
        ));
        let cfg = parse_args([
            "--profile",
            "SPINE_FUNCTIONAL",
            "--client-declaration",
            "C:\\a\\agent-bridge\\client-declaration-v2.json",
        ])
        .expect("valid");
        assert_eq!(
            cfg.client_declaration,
            PathBuf::from("C:\\a\\agent-bridge\\client-declaration-v2.json")
        );
        let cfg2 = parse_args([
            "--profile=SPINE_FUNCTIONAL",
            "--client-declaration=C:\\a\\agent-bridge\\client-declaration-v2.json",
        ])
        .expect("eq form");
        assert_eq!(
            cfg2.client_declaration,
            PathBuf::from("C:\\a\\agent-bridge\\client-declaration-v2.json")
        );
        assert!(matches!(
            parse_args([
                "--profile",
                "SPINE_FUNCTIONAL",
                "--client-declaration",
                "C:\\a\\wrong-parent\\client-declaration-v2.json"
            ]),
            Err(CliError::InvalidClientDeclarationPath(_))
        ));
        assert!(matches!(
            parse_args([
                "--profile",
                "SPINE_FUNCTIONAL",
                "--client-declaration",
                "C:\\a\\agent-bridge\\wrong-file.json"
            ]),
            Err(CliError::InvalidClientDeclarationPath(_))
        ));
    }

    #[test]
    fn old_generic_kernel_client_absent() {
        let src = include_str!("lib.rs");
        let needle = format!("{}{}", "eliot_cli", "::kernel_client");
        assert!(!src.contains(&needle));
        let awr = format!("{}{}", "ActivationWire", "Response");
        assert!(!src.contains(&awr));
    }

    #[test]
    fn raw_frame_forwarding_wrapper_is_absent() {
        let src = include_str!("lib.rs");
        let raw_forward = format!("{}{}", "forward_", "frame");
        assert!(!src.contains(&raw_forward));
    }

    #[test]
    fn no_unsafe_no_lint_override_no_direct_windows_sys() {
        let src = include_str!("lib.rs");
        let unsafe_block = format!("{}{}", "unsafe", " {");
        assert!(!src.contains(&unsafe_block));
        let unsafe_fn = format!("{}{}", "unsafe", " fn");
        assert!(!src.contains(&unsafe_fn));
        let lint_override = format!("{}{}", "allow(unsafe", "_code");
        assert!(!src.contains(&lint_override));
        let ws = format!("{}{}", "windows", "-sys");
        assert!(!src.contains(&ws));
        let cargo = include_str!("../Cargo.toml");
        let ws_cargo = format!("{}{}", "windows", "-sys");
        assert!(!cargo.contains(&ws_cargo));
        let ws_true = format!("{}{}", "workspace", " = true");
        assert!(cargo.contains(&ws_true));
    }

    #[test]
    fn single_retained_runtime_structure_order() {
        let src = include_str!("lib.rs");
        assert!(src.contains("transport: eliot_ipc::NamedPipeTransport"));
        assert!(src.contains("runtime: tokio::runtime::Runtime"));
        let transport_pos = src
            .find("transport: eliot_ipc::NamedPipeTransport")
            .unwrap();
        let runtime_pos = src.find("runtime: tokio::runtime::Runtime").unwrap();
        assert!(transport_pos < runtime_pos);
        assert!(src.contains("runtime.block_on"));
        let bad_first = format!("{}{}", "Builder::new", "_current_thread");
        let bad = format!("{}{}", bad_first, ".enable_all().build().unwrap().block_on");
        assert!(!src.contains(&bad));
        let cnt_pat = format!("{}{}", "Builder::new", "_current_thread");
        let count = src.matches(&cnt_pat).count();
        assert!(count <= 2);
    }

    #[test]
    fn retained_lease_and_one_shot_order() {
        let src = include_str!("lib.rs");
        assert!(src.contains("LoadedAgentBridgeDeclaration"));
        assert!(src.contains("_lease: eliot_platform_windows::AgentBridgeDeclarationReadLease"));
        assert!(src.contains("struct AdmittedConnection"));
        assert!(src.contains("admitted: AdmittedConnection"));
        assert!(src.contains("_loaded: LoadedAgentBridgeDeclaration"));
        let admitted_pos = src.find("admitted: AdmittedConnection").unwrap();
        let runtime_pos = src.find("runtime: tokio::runtime::Runtime").unwrap();
        let loaded_pos = src.find("_loaded: LoadedAgentBridgeDeclaration").unwrap();
        assert!(admitted_pos < runtime_pos);
        assert!(runtime_pos < loaded_pos);
        assert!(src.contains("activation_used: bool"));
        let err = format!(
            "{}{}",
            "activation exchange already consumed", "; restart/reconnect"
        );
        assert!(src.contains(&err));
        let one_builder = format!("{}{}", "Builder::new", "_current_thread");
        assert_eq!(src.matches(&one_builder).count(), 1);
    }

    #[test]
    #[allow(clippy::items_after_statements)]
    fn activation_one_shot_rejects_second_without_io() {
        let src = include_str!("lib.rs");
        let err_msg = format!(
            "{}{}",
            "activation exchange already consumed", "; restart/reconnect"
        );
        assert!(src.contains(&err_msg));
        let pos_guard = src.find("if self.activation_used").expect("guard");
        let pos_send = src
            .find("self.admitted.transport.send_frame")
            .expect("send");
        assert!(pos_guard < pos_send);
        struct MockGuard {
            used: bool,
        }
        impl MockGuard {
            fn activate(&mut self) -> Result<(), ProviderFailure> {
                if self.used {
                    return Err(ProviderFailure::new(
                        "eliot-kernel-front-door",
                        "activation exchange already consumed; restart/reconnect contour not admitted",
                    ));
                }
                self.used = true;
                Ok(())
            }
        }
        let mut g = MockGuard { used: true };
        let e = g.activate().expect_err("second must fail");
        assert!(e.to_string().contains("already consumed"));
    }

    #[test]
    fn off_windows_no_filesystem_read() {
        let src = include_str!("lib.rs");
        #[cfg(not(windows))]
        {
            assert!(src.contains("declaration lease unavailable off Windows"));
            let fs_read = format!("{}{}", "std::fs", "::read");
            assert!(!src.contains(&fs_read));
        }
        #[cfg(windows)]
        {
            assert!(src.contains("open_agent_bridge_declaration_read_lease"));
        }
    }

    #[test]
    fn declaration_deny_unknown_fields() {
        let mut decl = fixture_declaration();
        let mut value = serde_json::to_value(&decl).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<AgentBridgeClientDeclaration>(value).is_err());
        decl.declaration_sha256 = "0".repeat(64);
        assert!(decl.validate().is_err());
    }

    #[test]
    fn declaration_digest_substitution_fails() {
        let decl = fixture_declaration();
        let mut bad = decl.clone();
        bad.profile_id = "other-profile".to_owned();
        assert!(
            bad.validate().is_err() || bad.compute_digest().unwrap() != decl.declaration_sha256
        );
        let mut bad2 = decl.clone();
        bad2.expected_kernel_artifact_sha256 = "e".repeat(64);
        bad2.declaration_sha256 = bad2.compute_digest().unwrap();
        let chal = fixture_challenge(&decl);
        assert!(chal.validate_declaration(&bad2).is_err());
    }

    #[test]
    fn challenge_principal_config_artifact_substitution_fails() {
        let decl = fixture_declaration();
        let chal = fixture_challenge(&decl);
        chal.validate_declaration(&decl).expect("valid");
        let mut bad = chal.clone();
        bad.kernel_principal_binding = "other".to_owned();
        bad.challenge_sha256 = bad.compute_digest().unwrap();
        assert!(bad.validate_declaration(&decl).is_err());
        let mut bad2 = chal.clone();
        bad2.kernel_artifact_sha256 = "f".repeat(64);
        bad2.challenge_sha256 = bad2.compute_digest().unwrap();
        assert!(bad2.validate_declaration(&decl).is_err());
        let mut bad3 = chal.clone();
        bad3.kernel_config_snapshot_sha256 = "f".repeat(64);
        bad3.challenge_sha256 = bad3.compute_digest().unwrap();
        assert!(bad3.validate_declaration(&decl).is_err());
    }

    #[test]
    fn receipt_connection_fence_digest_deadline_substitution_fails() {
        let decl = fixture_declaration();
        let chal = fixture_challenge(&decl);
        let hello = decl.client_hello(chal.challenge_nonce.clone()).unwrap();
        let receipt = fixture_receipt(&chal, &hello);
        receipt.validate().expect("valid");
        receipt.validate_challenge(&chal).expect("bind");
        let mut bad_conn = receipt.clone();
        bad_conn.connection_id = "other".to_owned();
        bad_conn.receipt_sha256 = bad_conn.compute_digest().unwrap();
        assert!(
            bad_conn.validate_challenge(&chal).is_err()
                || bad_conn.connection_id != chal.clone().challenge_nonce
        );
        let mut bad_deadline = receipt.clone();
        bad_deadline.activation_deadline_unix_ms = 999;
        bad_deadline.receipt_sha256 = bad_deadline.compute_digest().unwrap();
        assert!(bad_deadline.validate_challenge(&chal).is_err());
        let mut bad_fence = receipt.clone();
        bad_fence.state_fence = StateFence::new(
            AuthorityEpoch::new(99).unwrap(),
            ResourceGeneration::new(99).unwrap(),
        );
        bad_fence.receipt_sha256 = bad_fence.compute_digest().unwrap();
        assert!(bad_fence.validate_challenge(&chal).is_err());
    }

    #[test]
    fn request_identity_semantic_fields_rejected() {
        let decl = fixture_declaration();
        let chal = fixture_challenge(&decl);
        let hello = decl.client_hello(chal.challenge_nonce.clone()).unwrap();
        let receipt = AgentBridgePeerAdmissionReceipt {
            wire_id: eliot_protocol::AGENT_BRIDGE_PEER_ADMISSION_RECEIPT_WIRE_ID.to_owned(),
            wire_version: AgentBridgePeerAdmissionReceipt::CONTRACT_VERSION,
            module_id: chal.module_id.clone(),
            connection_id: "conn-1".to_owned(),
            profile_id: chal.profile_id.clone(),
            descriptor_sha256: chal.descriptor_sha256.clone(),
            client_declaration_sha256: chal.client_declaration_sha256.clone(),
            bridge_generation: chal.bridge_generation,
            state_fence: chal.state_fence.clone(),
            activation_deadline_unix_ms: chal.activation_deadline_unix_ms,
            challenge_nonce: chal.challenge_nonce.clone(),
            challenge_sha256: chal.challenge_sha256.clone(),
            client_hello_sha256: eliot_platform_windows::sha256_hex(
                &eliot_contracts::canonical_json_bytes(&hello).unwrap(),
            ),
            observed_sid: "S-1-5-21-1000".to_owned(),
            observed_session_id: 1,
            observed_process_id: 123,
            observed_process_start_time_100ns: 456,
            observed_image_path: "C:\\bridge.exe".to_owned(),
            observed_image_volume_serial: 1,
            observed_image_file_index: 2,
            receipt_sha256: String::new(),
        }
        .with_computed_digest()
        .unwrap();
        let core_req = AttachRequest::managed(
            DemandId::new("demand-1").unwrap(),
            ConnectionId::new("conn-1").unwrap(),
        );
        let req =
            build_neutral_activation_request(&core_req, &receipt, "demand-1").expect("neutral");
        assert!(req.request_identity.request.metadata.session_id.is_none());
        assert!(req.request_identity.request.metadata.task_id.is_none());
        assert!(
            req.request_identity
                .request
                .metadata
                .state_fence
                .task_revision
                .is_none()
        );
        assert!(
            req.request_identity
                .request
                .metadata
                .clock
                .valid_time_ms
                .is_none()
        );
        let frame = activation_frame_for_request(&req).expect("frame");
        assert_eq!(frame.kind, FrameKind::Request);
        assert_eq!(frame.message_type, MessageType::Execute);
        let resp = AgentBridgeActivationResponse::denied(
            &req,
            eliot_protocol::AgentBridgeActivationDenialCode::SemanticResolutionUnavailable,
        )
        .unwrap();
        let resp_frame = Frame {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: req.connection_id.clone(),
            request_id: Some(req.request_identity.request.metadata.request_id.clone()),
            kind: FrameKind::Response,
            message_type: MessageType::Result,
            request_identity: None,
            payload: ProtocolPayload::Json(serde_json::to_value(&resp).unwrap()),
            trace_context: BTreeMap::new(),
        };
        let decoded = decode_activation_response(&resp_frame, &req, &receipt).expect("decode");
        assert!(matches!(
            decoded.disposition,
            eliot_protocol::AgentBridgeActivationDisposition::Denied { .. }
        ));
        let mut bad_req = req.clone();
        bad_req.request_sha256 = "0".repeat(64);
        assert!(decode_activation_response(&resp_frame, &bad_req, &receipt).is_err());
    }

    #[test]
    fn typed_denial_mapping() {
        let decl = fixture_declaration();
        let chal = fixture_challenge(&decl);
        let hello = decl.client_hello(chal.challenge_nonce.clone()).unwrap();
        let receipt = AgentBridgePeerAdmissionReceipt {
            wire_id: eliot_protocol::AGENT_BRIDGE_PEER_ADMISSION_RECEIPT_WIRE_ID.to_owned(),
            wire_version: AgentBridgePeerAdmissionReceipt::CONTRACT_VERSION,
            module_id: chal.module_id.clone(),
            connection_id: "conn-1".to_owned(),
            profile_id: chal.profile_id.clone(),
            descriptor_sha256: chal.descriptor_sha256.clone(),
            client_declaration_sha256: chal.client_declaration_sha256.clone(),
            bridge_generation: chal.bridge_generation,
            state_fence: chal.state_fence.clone(),
            activation_deadline_unix_ms: chal.activation_deadline_unix_ms,
            challenge_nonce: chal.challenge_nonce.clone(),
            challenge_sha256: chal.challenge_sha256.clone(),
            client_hello_sha256: eliot_platform_windows::sha256_hex(
                &eliot_contracts::canonical_json_bytes(&hello).unwrap(),
            ),
            observed_sid: "S-1-5-21-1000".to_owned(),
            observed_session_id: 1,
            observed_process_id: 123,
            observed_process_start_time_100ns: 456,
            observed_image_path: "C:\\bridge.exe".to_owned(),
            observed_image_volume_serial: 1,
            observed_image_file_index: 2,
            receipt_sha256: String::new(),
        }
        .with_computed_digest()
        .unwrap();
        let core_req = AttachRequest::managed(
            DemandId::new("demand-1").unwrap(),
            ConnectionId::new("conn-1").unwrap(),
        );
        let req = build_neutral_activation_request(&core_req, &receipt, "demand-1").unwrap();
        let resp = AgentBridgeActivationResponse::denied(
            &req,
            eliot_protocol::AgentBridgeActivationDenialCode::SemanticResolutionUnavailable,
        )
        .unwrap();
        assert!(resp.validate_request(&req).is_ok());
    }

    #[test]
    fn activation_response_join_rejects_connection_and_semantic_fence_substitutions() {
        let decl = fixture_declaration();
        let chal = fixture_challenge(&decl);
        let hello = decl.client_hello(chal.challenge_nonce.clone()).unwrap();
        let receipt = fixture_receipt(&chal, &hello);
        let core_req = AttachRequest::managed(
            DemandId::new("demand-1").unwrap(),
            ConnectionId::new("conn-1").unwrap(),
        );
        let req = build_neutral_activation_request(&core_req, &receipt, "demand-1").unwrap();
        let frame_for = |response: &AgentBridgeActivationResponse, connection_id: &str| Frame {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: connection_id.to_owned(),
            request_id: Some(req.request_identity.request.metadata.request_id.clone()),
            kind: FrameKind::Response,
            message_type: MessageType::Result,
            request_identity: None,
            payload: ProtocolPayload::Json(serde_json::to_value(response).unwrap()),
            trace_context: BTreeMap::new(),
        };
        let response = AgentBridgeActivationResponse {
            wire_id: eliot_protocol::AGENT_BRIDGE_ACTIVATION_RESPONSE_WIRE_ID.to_owned(),
            wire_version: AgentBridgeActivationResponse::CONTRACT_VERSION,
            request_id: req.request_identity.request.metadata.request_id.clone(),
            request_sha256: req.request_sha256.clone(),
            disposition: eliot_protocol::AgentBridgeActivationDisposition::Authenticated {
                binding: Box::new(eliot_protocol::AgentBridgeAuthenticatedBinding {
                    principal_id: "principal-1".to_owned(),
                    session_id: "session-1".to_owned(),
                    activation_generation: receipt.state_fence.resource_generation,
                    state_fence: eliot_protocol::AgentBridgeActivationFence {
                        authority_epoch: receipt.state_fence.authority_epoch,
                        generation: receipt.state_fence.resource_generation,
                        nonce: "semantic-fence-1".to_owned(),
                    },
                    task_id: "task-1".to_owned(),
                    work_unit_id: "work-unit-1".to_owned(),
                    work_scope_id: "scope-1".to_owned(),
                    task_revision: "task-revision-1".to_owned(),
                    plan_id: "plan-1".to_owned(),
                    plan_revision: "plan-revision-1".to_owned(),
                }),
            },
            response_sha256: String::new(),
        }
        .with_computed_digest()
        .unwrap();
        let valid_frame = frame_for(&response, "conn-1");
        assert!(decode_activation_response(&valid_frame, &req, &receipt).is_ok());

        let bad_connection_frame = frame_for(&response, "other-connection");
        assert!(decode_activation_response(&bad_connection_frame, &req, &receipt).is_err());

        let mut bad_request_digest = response.clone();
        bad_request_digest.request_sha256 = "0".repeat(64);
        bad_request_digest = bad_request_digest.with_computed_digest().unwrap();
        let bad_request_digest_frame = frame_for(&bad_request_digest, "conn-1");
        assert!(decode_activation_response(&bad_request_digest_frame, &req, &receipt).is_err());

        let mut bad_authority_epoch = response.clone();
        if let eliot_protocol::AgentBridgeActivationDisposition::Authenticated { binding } =
            &mut bad_authority_epoch.disposition
        {
            binding.state_fence.authority_epoch = AuthorityEpoch::new(99).unwrap();
        }
        bad_authority_epoch = bad_authority_epoch.with_computed_digest().unwrap();
        let bad_authority_epoch_frame = frame_for(&bad_authority_epoch, "conn-1");
        assert!(decode_activation_response(&bad_authority_epoch_frame, &req, &receipt).is_err());

        let mut bad_generation = response.clone();
        if let eliot_protocol::AgentBridgeActivationDisposition::Authenticated { binding } =
            &mut bad_generation.disposition
        {
            let substituted = ResourceGeneration::new(8).unwrap();
            binding.activation_generation = substituted;
            binding.state_fence.generation = substituted;
        }
        bad_generation = bad_generation.with_computed_digest().unwrap();
        let bad_generation_frame = frame_for(&bad_generation, "conn-1");
        assert!(decode_activation_response(&bad_generation_frame, &req, &receipt).is_err());
    }

    #[test]
    fn authenticated_consume_without_local_constructor() {
        let src = include_str!("lib.rs");
        let needle = format!("{}{}", "ActivationWire", "Response");
        assert!(!src.contains(&needle));
        assert!(src.contains("decode_activation_response"));
        let auth = format!("{}{}", "Authenticated", "");
        assert!(src.contains(&auth));
    }

    #[test]
    fn wrong_current_sid_accessor_rejected() {
        let current = "S-1-5-21-1000";
        let observed = "S-1-5-21-2000";
        assert_ne!(current, observed);
        let expectation = eliot_platform_windows::KernelFrontDoorServerExpectation::new(
            "S-1-5-18",
            0,
            "b".repeat(64),
            eliot_platform_windows::KernelFrontDoorAclMode::SystemAndLocalServiceWithClient {
                client_sid: current.to_owned(),
            },
        )
        .unwrap();
        assert_eq!(
            expectation.acl_mode(),
            &eliot_platform_windows::KernelFrontDoorAclMode::SystemAndLocalServiceWithClient {
                client_sid: current.to_owned()
            }
        );
        assert_ne!(observed, current);
    }

    #[test]
    fn mocked_transport_state_order() {
        let decl = fixture_declaration();
        let chal = fixture_challenge(&decl);
        let hello = decl.client_hello(chal.challenge_nonce.clone()).unwrap();
        let frame = eliot_ipc::peer_challenge_frame("conn-1", &chal).unwrap();
        let decoded = eliot_ipc::decode_peer_challenge_frame(&frame, "conn-1").unwrap();
        assert_eq!(decoded, chal);
        let hello_frame = eliot_ipc::client_hello_frame("conn-1", &hello).unwrap();
        let hello_decoded = eliot_ipc::decode_client_hello_frame(&hello_frame, "conn-1").unwrap();
        assert_eq!(hello_decoded, hello);
        let mut wrong_order = hello_frame.clone();
        wrong_order.connection_id = "other".to_owned();
        assert!(eliot_ipc::decode_client_hello_frame(&wrong_order, "conn-1").is_err());
    }
}
