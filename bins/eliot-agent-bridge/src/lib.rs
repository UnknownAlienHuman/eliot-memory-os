//! B-15's thin profile-selected agent/host bridge.
//!
//! The runner is only composition: A-16 owns attach, reconnect, hook/event
//! forwarding, replay and coverage semantics; C0-07 owns frame validation and
//! framing; P-11 supplies bounded runtime mechanics. No provider, scheduler,
//! durable journal, secret, or semantic state is created here.

#![forbid(unsafe_code)]

use std::fmt;
use std::time::Duration;

use eliot_agent_bridge_core::{
    AgentBridgeCore, AttachRequest, AttachView, BridgeError, ConnectionId, CursorPolicy, DemandId,
    EventForwardStatus, HostActivationPort, HostEventEnvelope, McpForwardingPort,
    ProviderReadiness, ReconnectRequest,
};
use eliot_protocol::{AckPhase, EventEnvelope, Frame};
use eliot_runtime::{Runtime, RuntimeConfig};

/// The only B-15 composition profiles admitted by the canonical runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// The minimum functional ELIOT spine.
    SpineFunctional,
    /// The complete admitted composition.
    FullComposition,
}

impl Profile {
    /// Returns the canonical command-line spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SpineFunctional => "SPINE_FUNCTIONAL",
            Self::FullComposition => "FULL_COMPOSITION",
        }
    }

    /// Returns whether this profile was compiled into the current binary.
    #[must_use]
    pub const fn is_compiled(self) -> bool {
        match self {
            Self::SpineFunctional => cfg!(feature = "eliot-profile-spine-functional"),
            Self::FullComposition => cfg!(feature = "eliot-profile-full-composition"),
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A fail-closed profile/transport parse failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CliError {
    /// The required profile was omitted.
    MissingProfile,
    /// The profile is not one of the canonical admitted profiles.
    UnsupportedProfile(String),
    /// An argument was malformed or unknown.
    MalformedArgument(String),
    /// Remote transport selection is never admitted by B-15.
    RemoteTransportForbidden(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProfile => formatter.write_str("MISSING_PROFILE"),
            Self::UnsupportedProfile(profile) => {
                write!(formatter, "UNSUPPORTED_PROFILE:{profile}")
            }
            Self::MalformedArgument(argument) => write!(formatter, "MALFORMED_ARGUMENT:{argument}"),
            Self::RemoteTransportForbidden(transport) => {
                write!(formatter, "REMOTE_TRANSPORT_FORBIDDEN:{transport}")
            }
        }
    }
}

impl std::error::Error for CliError {}

impl std::str::FromStr for Profile {
    type Err = CliError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "SPINE_FUNCTIONAL" => Ok(Self::SpineFunctional),
            "FULL_COMPOSITION" => Ok(Self::FullComposition),
            other => Err(CliError::UnsupportedProfile(other.to_owned())),
        }
    }
}

/// The explicitly bounded transport selection. Stdio is the production
/// default; a loopback label remains reserved for a future injected port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    /// Length-delimited protocol frames over stdin/stdout.
    Stdio,
    /// A future local-only transport supplied by the composition owner.
    Loopback,
}

impl Transport {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "stdio" => Ok(Self::Stdio),
            "loopback" => Ok(Self::Loopback),
            other => Err(CliError::RemoteTransportForbidden(other.to_owned())),
        }
    }
}

/// Parsed B-15 command-line configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CliConfig {
    /// Selected canonical profile.
    pub profile: Profile,
    /// Selected bounded transport.
    pub transport: Transport,
}

/// Parses B-15 arguments without a general-purpose command-line dependency.
///
/// # Errors
///
/// Returns a typed error when the profile is missing/unknown, an argument is
/// malformed, or a non-loopback transport is requested.
pub fn parse_args<I, S>(arguments: I) -> Result<CliConfig, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let arguments: Vec<String> = arguments.into_iter().map(Into::into).collect();
    let mut profile = None;
    let mut transport = Transport::Stdio;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--profile" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument("--profile requires a value".to_owned())
                })?;
                profile = Some(value.parse()?);
                index += 2;
            }
            value if value.starts_with("--profile=") => {
                let value = value.trim_start_matches("--profile=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--profile= requires a value".to_owned(),
                    ));
                }
                profile = Some(value.parse()?);
                index += 1;
            }
            "--transport" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument("--transport requires a value".to_owned())
                })?;
                transport = Transport::parse(value)?;
                index += 2;
            }
            value if value.starts_with("--transport=") => {
                let value = value.trim_start_matches("--transport=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--transport= requires a value".to_owned(),
                    ));
                }
                transport = Transport::parse(value)?;
                index += 1;
            }
            value => return Err(CliError::MalformedArgument(value.to_owned())),
        }
    }
    Ok(CliConfig {
        profile: profile.ok_or(CliError::MissingProfile)?,
        transport,
    })
}

/// B-15's injected composition runner.
pub struct BridgeRunner {
    profile: Profile,
    runtime: Runtime,
    core: AgentBridgeCore,
}

impl BridgeRunner {
    /// Builds a runner from the three canonical production surfaces and
    /// injected host/MCP ports. The ports remain the sole provider boundary.
    ///
    /// # Errors
    ///
    /// Returns an error only when P-11 rejects the fixed runtime parameters or
    /// A-16 rejects the fixed acknowledgement cursor policy.
    pub fn new(
        profile: Profile,
        readiness: ProviderReadiness,
        host_activation: Option<Box<dyn HostActivationPort>>,
        mcp_forwarding: Option<Box<dyn McpForwardingPort>>,
    ) -> Result<Self, RuntimeBuildError> {
        if !profile.is_compiled() {
            return Err(RuntimeBuildError::ProfileUnavailable(profile));
        }
        let runtime = Runtime::new(
            RuntimeConfig {
                mailbox_capacity: 32,
                control_reserve: 4,
                concurrency: 1,
                control_concurrency_reserve: 1,
                fairness_quantum: 8,
                restart_budget: 0,
                restart_window: Duration::from_secs(60),
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

    /// Returns the selected composition profile.
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    /// Returns the runtime's available protected control capacity.
    #[must_use]
    pub fn control_capacity(&self) -> usize {
        self.runtime
            .available_capacity(eliot_runtime::ExecutionClass::ProtectedControl)
    }

    /// Performs the demand-start attach through the injected host port.
    ///
    /// # Errors
    ///
    /// Forwards A-16's typed unavailable, authentication, fence, generation,
    /// and provider errors without translating or weakening them.
    pub fn demand_start(
        &mut self,
        demand_id: impl Into<String>,
        connection_id: impl Into<String>,
    ) -> Result<AttachView, BridgeError> {
        self.core.attach(AttachRequest::managed(
            DemandId::new(demand_id)
                .map_err(|error| BridgeError::ProviderContract(error.to_string()))?,
            ConnectionId::new(connection_id)
                .map_err(|error| BridgeError::ProviderContract(error.to_string()))?,
        ))
    }

    /// Rebinds transport while preserving the exact authority binding.
    ///
    /// # Errors
    ///
    /// Returns A-16's stale-authority or not-attached error when the request
    /// does not match the active session, generation, and fence.
    pub fn reconnect(&mut self, request: ReconnectRequest) -> Result<AttachView, BridgeError> {
        self.core.reconnect(request)
    }

    /// Forwards a validated protocol frame through A-06's injected port.
    ///
    /// # Errors
    ///
    /// Returns A-16's typed attachment, transport, protocol, or provider
    /// error.
    pub fn forward_frame(&mut self, frame: &Frame) -> Result<(), BridgeError> {
        self.core.forward_frame(frame)
    }

    /// Forwards an exact host hook observation through A-06's injected port.
    ///
    /// # Errors
    ///
    /// Returns A-16's typed attachment, validation, or provider error without
    /// minting authority from the observation.
    pub fn forward_hook(&mut self, event: &HostEventEnvelope) -> Result<(), BridgeError> {
        self.core.forward_hook(event)
    }

    /// Forwards an `EventEnvelope` and returns A-16's explicit delivery result.
    ///
    /// # Errors
    ///
    /// Returns A-16's typed replay, acknowledgement, fence, attachment, or
    /// provider error.
    pub fn forward_event(
        &mut self,
        event: &EventEnvelope,
    ) -> Result<EventForwardStatus, BridgeError> {
        self.core.forward_event(event)
    }

    /// Exposes the read-only current attach view.
    #[must_use]
    pub fn attach_view(&self) -> Option<AttachView> {
        self.core.attach_view()
    }

    /// Returns a concise unavailable result for the real binary path. Main
    /// intentionally supplies no host/kernel providers until composition
    /// admits them; this method must never be interpreted as launch success.
    ///
    /// # Errors
    ///
    /// Returns a P-11/A-16 construction error if the fixed composition cannot
    /// be built.
    pub fn unavailable(profile: Profile) -> Result<Self, RuntimeBuildError> {
        Self::new(
            profile,
            ProviderReadiness::all_admitted()
                .with_unavailable(eliot_agent_bridge_core::RequiredProvider::HostActivationPort),
            None,
            None,
        )
    }
}

/// Runner construction failures, kept independent from provider state.
#[derive(Debug)]
pub enum RuntimeBuildError {
    /// The requested profile was not compiled into this binary.
    ProfileUnavailable(Profile),
    /// P-11 rejected the explicit bounded runtime configuration.
    Runtime(eliot_runtime::ConfigError),
    /// A-16 rejected the fixed cursor policy.
    BridgeContract(BridgeError),
}

impl fmt::Display for RuntimeBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProfileUnavailable(profile) => {
                write!(formatter, "PLAN_GAP:PROFILE_UNAVAILABLE:{profile}")
            }
            Self::Runtime(_) => formatter.write_str("RUNTIME_CONFIG_INVALID"),
            Self::BridgeContract(error) => write!(formatter, "BRIDGE_CONTRACT_INVALID:{error}"),
        }
    }
}

impl std::error::Error for RuntimeBuildError {}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::{Arc, Mutex};

    use eliot_agent_bridge_core::{
        ActivationPortOutcome, ActivationPortResult, AttachBinding, AttemptId, EventCursor,
        EventId, EventPortOutcome, FencingToken, Generation, HostActivationPort, HostEventEnvelope,
        HostEventKind, McpForwardingPort, PrincipalId, ProviderFailure, ProviderReadiness,
        RouteFingerprint, SessionId, TaskId, WorkUnitId,
    };
    use eliot_protocol::{
        EncodingProfile, EventEnvelope, Frame, FrameKind, JsonCodec, MessageType, ProtocolError,
        ProtocolPayload, ProtocolVersion,
    };

    use super::{CliError, Profile, Transport, parse_args};

    #[derive(Default)]
    struct FakeCounts {
        frames: usize,
        hooks: usize,
    }

    struct FakeHost {
        activations: VecDeque<ActivationPortOutcome>,
    }

    impl HostActivationPort for FakeHost {
        fn activate(
            &mut self,
            _request: &eliot_agent_bridge_core::AttachRequest,
        ) -> Result<ActivationPortOutcome, ProviderFailure> {
            self.activations
                .pop_front()
                .ok_or(ProviderFailure::new("test", "missing activation fixture"))
        }
    }

    struct FakeForwarder {
        counts: Arc<Mutex<FakeCounts>>,
    }

    impl McpForwardingPort for FakeForwarder {
        fn forward_frame(
            &mut self,
            _binding: &AttachBinding,
            _frame: &Frame,
        ) -> Result<(), ProviderFailure> {
            self.counts
                .lock()
                .map_err(|_| ProviderFailure::new("test", "lock"))?
                .frames += 1;
            Ok(())
        }

        fn forward_hook(
            &mut self,
            _binding: &AttachBinding,
            _event: &HostEventEnvelope,
        ) -> Result<(), ProviderFailure> {
            self.counts
                .lock()
                .map_err(|_| ProviderFailure::new("test", "lock"))?
                .hooks += 1;
            Ok(())
        }

        fn forward_event(
            &mut self,
            _binding: &AttachBinding,
            _event: &EventEnvelope,
        ) -> Result<EventPortOutcome, ProviderFailure> {
            Ok(EventPortOutcome::BestEffortForwarded)
        }

        fn forward_gap(
            &mut self,
            _binding: &AttachBinding,
            _gap: &eliot_agent_bridge_core::CoverageGap,
        ) -> Result<(), ProviderFailure> {
            Ok(())
        }

        fn reconcile_external(
            &mut self,
            _binding: &AttachBinding,
        ) -> Result<eliot_agent_bridge_core::ReconciliationPortOutcome, ProviderFailure> {
            Err(ProviderFailure::new("test", "not used"))
        }
    }

    fn activation(task: &str, work_unit: &str, suffix: &str) -> ActivationPortOutcome {
        let generation = Generation::new(1).expect("fixture generation");
        let fence = FencingToken::new(1, generation, format!("fixture-fence-{suffix}"))
            .expect("fixture fence");
        ActivationPortOutcome::Authenticated(
            ActivationPortResult::authenticated(
                PrincipalId::new("fixture-principal").expect("fixture principal"),
                SessionId::new(format!("fixture-session-{suffix}")).expect("fixture session"),
                generation,
                fence,
                TaskId::new(task).expect("fixture task"),
                WorkUnitId::new(work_unit).expect("fixture work unit"),
                "fixture-scope",
                "task-revision-1",
                "plan-1",
                "plan-revision-1",
            )
            .expect("fixture activation"),
        )
    }

    fn injected_runner() -> (super::BridgeRunner, Arc<Mutex<FakeCounts>>) {
        let counts = Arc::new(Mutex::new(FakeCounts::default()));
        let runner = super::BridgeRunner::new(
            test_profile(),
            ProviderReadiness::all_admitted(),
            Some(Box::new(FakeHost {
                activations: VecDeque::from([activation("fixture-task", "fixture-work", "one")]),
            })),
            Some(Box::new(FakeForwarder {
                counts: Arc::clone(&counts),
            })),
        )
        .expect("runner fixture");
        (runner, counts)
    }

    #[allow(clippy::default_trait_access)]
    fn frame() -> Frame {
        Frame {
            protocol_version: ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: "fixture-connection".to_owned(),
            request_id: None,
            kind: FrameKind::Heartbeat,
            message_type: MessageType::Health,
            request_identity: None,
            payload: ProtocolPayload::Json(Default::default()),
            trace_context: BTreeMap::new(),
        }
    }

    #[allow(clippy::default_trait_access)]
    fn hook() -> HostEventEnvelope {
        HostEventEnvelope {
            event_id: EventId::new("hook-1").expect("fixture event id"),
            attempt_id: AttemptId::new("attempt-1").expect("fixture attempt id"),
            sequence: 1,
            cursor: EventCursor::new("cursor-1").expect("fixture cursor"),
            kind: HostEventKind::ToolResult,
            route: RouteFingerprint {
                host_family: "test".to_owned(),
                adapter: "test".to_owned(),
                protocol_transport: "stdio".to_owned(),
                runtime_hash: "runtime".to_owned(),
                adapter_hash: "adapter".to_owned(),
                provider: "provider".to_owned(),
                model: "model".to_owned(),
                auth_billing: "test".to_owned(),
                serializer_hash: "serializer".to_owned(),
                tool_semantics_hash: "tools".to_owned(),
                reasoning_mode: "test".to_owned(),
                continuation_behavior: "fresh".to_owned(),
                feature_flags_hash: "flags".to_owned(),
            },
            raw_payload_digest: "digest".to_owned(),
            normalized_payload: Default::default(),
            parent_event_id: None,
            observed_at: "2026-08-14T00:00:00Z".to_owned(),
        }
    }

    fn test_profile() -> Profile {
        if Profile::SpineFunctional.is_compiled() {
            Profile::SpineFunctional
        } else {
            Profile::FullComposition
        }
    }

    #[test]
    fn only_canonical_profiles_are_admitted() {
        assert_eq!("SPINE_FUNCTIONAL".parse(), Ok(Profile::SpineFunctional));
        assert_eq!("FULL_COMPOSITION".parse(), Ok(Profile::FullComposition));
        assert!(matches!(
            "spine_functional".parse::<Profile>(),
            Err(CliError::UnsupportedProfile(_))
        ));
        assert!(matches!(
            parse_args(["--profile", "FULL_COMPOSITION"]),
            Ok(config) if config.transport == Transport::Stdio
        ));
    }

    #[test]
    fn malformed_missing_and_remote_inputs_fail_closed() {
        assert_eq!(parse_args::<_, &str>([]), Err(CliError::MissingProfile));
        assert!(matches!(
            parse_args([
                "--profile",
                "SPINE_FUNCTIONAL",
                "--transport",
                "tcp://127.0.0.1"
            ]),
            Err(CliError::RemoteTransportForbidden(_))
        ));
        assert!(matches!(
            parse_args(["--profile", "SPINE_FUNCTIONAL", "--profile"]),
            Err(CliError::MalformedArgument(_))
        ));
    }

    #[test]
    fn injected_demand_attach_frame_and_hook_event_forwarding_stay_thin() {
        let (mut runner, counts) = injected_runner();
        let view = runner
            .demand_start("fixture-demand", "fixture-connection")
            .expect("attach");
        assert_eq!(view.binding().session_id().as_str(), "fixture-session-one");
        assert_eq!(
            view.binding().task_binding().task_id().as_str(),
            "fixture-task"
        );
        assert_eq!(
            view.binding().task_binding().work_unit_id().as_str(),
            "fixture-work"
        );
        assert_eq!(
            view.binding().task_binding().work_scope_id(),
            "fixture-scope"
        );
        assert_eq!(
            view.binding().task_binding().task_revision(),
            "task-revision-1"
        );
        assert_eq!(view.binding().task_binding().plan_id(), "plan-1");
        assert_eq!(
            view.binding().task_binding().plan_revision(),
            "plan-revision-1"
        );
        runner.forward_frame(&frame()).expect("frame forwarding");
        let counts = counts.lock().expect("fixture counts");
        assert_eq!(counts.frames, 1);
    }

    #[test]
    fn public_hook_forward_path_delegates_through_runner_surface() {
        let (mut runner, counts) = injected_runner();
        runner
            .demand_start("fixture-demand", "fixture-connection")
            .expect("attach");
        runner.forward_hook(&hook()).expect("hook forwarding");
        let counts = counts.lock().expect("fixture counts");
        assert_eq!(counts.hooks, 1);
    }

    #[test]
    fn unavailable_binary_composition_is_a_typed_plan_gap() {
        let profile = test_profile();
        let mut runner = super::BridgeRunner::unavailable(profile).expect("runner");
        assert!(matches!(
            runner.demand_start("demand", "connection"),
            Err(eliot_agent_bridge_core::BridgeError::PlanGap(_))
        ));
    }

    #[test]
    fn task_binding_survives_reconnect_and_mismatch_is_rejected() {
        let counts = Arc::new(Mutex::new(FakeCounts::default()));
        let mut runner = super::BridgeRunner::new(
            test_profile(),
            ProviderReadiness::all_admitted(),
            Some(Box::new(FakeHost {
                activations: VecDeque::from([activation("task-a", "work-a", "one")]),
            })),
            Some(Box::new(FakeForwarder {
                counts: Arc::clone(&counts),
            })),
        )
        .expect("runner fixture");
        let first = runner
            .demand_start("fixture-demand", "fixture-connection")
            .expect("attach");
        let generation = Generation::new(1).expect("generation");
        let fence = FencingToken::new(1, generation, "fixture-fence-one").expect("fence");
        let reconnected = runner
            .reconnect(
                eliot_agent_bridge_core::ReconnectRequest::new(
                    SessionId::new("fixture-session-one").expect("session"),
                    generation,
                    fence,
                    eliot_agent_bridge_core::ConnectionId::new("fixture-connection-2")
                        .expect("connection"),
                )
                .expect("reconnect request"),
            )
            .expect("reconnect");
        assert_eq!(
            reconnected.binding().task_binding(),
            first.binding().task_binding()
        );

        let counts = Arc::new(Mutex::new(FakeCounts::default()));
        let mut mismatch_runner = super::BridgeRunner::new(
            test_profile(),
            ProviderReadiness::all_admitted(),
            Some(Box::new(FakeHost {
                activations: VecDeque::from([
                    activation("task-a", "work-a", "one"),
                    activation("task-b", "work-b", "two"),
                ]),
            })),
            Some(Box::new(FakeForwarder { counts })),
        )
        .expect("mismatch runner fixture");
        mismatch_runner
            .demand_start("fixture-demand", "fixture-connection")
            .expect("first attach");
        assert!(matches!(
            mismatch_runner.demand_start("fixture-demand-2", "fixture-connection-2"),
            Err(eliot_agent_bridge_core::BridgeError::StaleAuthority)
        ));
    }

    #[test]
    fn canonical_protocol_codec_rejects_malformed_partial_oversize_and_trailing_frames() {
        let codec = JsonCodec::new();
        let encoded = codec.encode(&frame()).expect("encoded fixture frame");
        assert!(matches!(
            codec.decode(&encoded[..3]),
            Err(ProtocolError::PartialFrame { .. })
        ));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(codec.decode(&trailing), Err(ProtocolError::TrailingBytes));
        assert!(matches!(
            JsonCodec::with_max_frame_bytes(1).encode(&frame()),
            Err(ProtocolError::OversizeFrame { .. })
        ));
        let malformed = [1_u8, 0, 0, 0, b'{'];
        assert!(matches!(
            codec.decode(&malformed),
            Err(ProtocolError::Json(_))
        ));
    }
}
