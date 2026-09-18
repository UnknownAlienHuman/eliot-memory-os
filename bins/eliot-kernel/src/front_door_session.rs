//! Kernel front-door session binding and peer identity validation.
//!
//! Traceability: Architecture A2.3, A12.2, A12.3, A13.2;
//! principles ARCH-AUTH-01, ARCH-SEC-01, ARCH-SEC-02.
//! Implementation I1.2, I1.8, I7.1, I7.3, I7.5, I7.14, I15.2, P.3, I2.23.
//!
//! This module owns the Windows-first transport selection and limits,
//! authenticated peer-set construction/snapshot, and Kernel-side session
//! binding. It validates generation-bound `eliotd` identity and fails closed
//! on poisoned or stale state; it does not dispatch frames, grant semantic
//! authority, or persist canonical transitions.

use super::*;

fn observe_front_door_session(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "front-door session observation"
    );
}

#[cfg(windows)]
fn observe_peer_snapshot(revision: u64, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = "kernel.front_door_peer_set_snapshot",
        revision = revision,
        outcome = outcome_bound.text(),
        "front-door peer-set snapshot observation"
    );
}

#[cfg(windows)]
fn peer_set_terminal_code(_: &KernelBuildError) -> &'static str {
    "peer_set_fenced"
}

fn transport_terminal_code(error: &eliot_ipc::TransportError) -> &'static str {
    match error {
        eliot_ipc::TransportError::SessionFenced => "session_fenced",
        eliot_ipc::TransportError::PeerIdentityUnavailable => "peer_identity_unavailable",
        eliot_ipc::TransportError::UnauthenticatedPeer => "unauthenticated_peer",
        eliot_ipc::TransportError::Timeout => "timeout",
        eliot_ipc::TransportError::UnknownRequest => "unknown_request",
        eliot_ipc::TransportError::UnknownOutcome => "unknown_outcome",
        eliot_ipc::TransportError::IdentityConflict => "identity_conflict",
        eliot_ipc::TransportError::Cancelled => "cancelled",
        eliot_ipc::TransportError::Backpressure => "backpressure",
        eliot_ipc::TransportError::InvalidLimits => "invalid_limits",
        eliot_ipc::TransportError::InvalidPipeName => "invalid_pipe_name",
        eliot_ipc::TransportError::RegistryFull => "registry_full",
        eliot_ipc::TransportError::Io(_) => "transport_io",
        eliot_ipc::TransportError::PlanGap { .. } => "plan_gap",
        eliot_ipc::TransportError::Protocol(_) => "protocol",
    }
}

/// Stable module identity of the one-shot Doctor repair worker (T6-D2 P-07).
///
/// The Doctor never self-asserts authority through this string:
/// [`KernelComposition::bind_session`] admits it only over an already
/// pipe-authenticated peer whose `ClientHello` is proven generation-bound
/// against the live server policy by
/// [`KernelComposition::validate_doctor_client_binding`].
///
/// NOTE (platform boundary): the OS pipe peer set
/// (`NamedPipePeerSet`, `MAX_ENTRIES = 3`) admits exactly one Host, Eliotd,
/// and `AgentBridge` role and lives in `eliot-platform-windows`, outside Slice-B
/// scope. A dedicated fourth OS Doctor role needs that platform change; until
/// then the Doctor rides an already-authenticated pipe peer and is bound at
/// session scope here. Invalid peer or epoch gets no protected input.
pub(crate) const DOCTOR_MODULE_ID: &str = "eliot-doctor";

/// Stable module identity of the one-shot testd admission worker (T6-X1 P-07).
///
/// Testd never self-asserts authority through this string:
/// [`KernelComposition::bind_session`] admits it only over an already
/// pipe-authenticated peer whose `ClientHello` is proven generation-bound
/// against the live server policy by
/// [`KernelComposition::validate_testd_client_binding`].
///
/// NOTE (platform boundary): the OS pipe peer set
/// (`NamedPipePeerSet`, `MAX_ENTRIES = 3`) admits exactly one Host, Eliotd,
/// and `AgentBridge` role and lives in `eliot-platform-windows`, outside Slice-B
/// scope. A dedicated fourth OS testd role needs that platform change; until
/// then testd rides an already-authenticated pipe peer and is bound at
/// session scope here. Invalid peer or epoch gets no protected input.
pub(crate) const TESTD_MODULE_ID: &str = "eliot-testd";

/// Stable module identity of the one-shot native-worker claim worker
/// (DISPATCH-CAUSE-FIX, issues #461/#20/#22).
///
/// The native worker never self-asserts authority through this string:
/// [`KernelComposition::bind_session`] admits it only over an already
/// pipe-authenticated peer whose `ClientHello` is proven generation-bound
/// against the live server policy by
/// [`KernelComposition::validate_native_worker_client_binding`].
///
/// NOTE (front-door reuse): no dedicated `AuthenticatedNativeWorkerSession`
/// type exists on this base, so the module binds through the same
/// front-door session mechanism Doctor/Testd use (generation-bound
/// `ClientHello` proof plus least-privilege capabilities intersected down
/// to the single admitted native-worker claim wire). See
/// [`KernelComposition::bind_native_worker_session`].
///
/// NOTE (platform boundary): like Doctor/Testd, the native worker rides an
/// already-authenticated pipe peer until a dedicated OS role lands.
pub(crate) const NATIVE_MODULE_ID: &str = "eliot-native-worker";

/// The only transport implementation admitted by the Windows-first Kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum IpcImplementation {
    /// Local authenticated EBP/1 named pipe.
    WindowsNamedPipe { name: String },
}

impl IpcImplementation {
    pub(super) fn new(name: impl Into<String>) -> Result<Self, KernelBuildError> {
        let name = name.into();
        eliot_ipc::validate_pipe_name(&name).map_err(KernelBuildError::Transport)?;
        Ok(Self::WindowsNamedPipe { name })
    }

    /// Returns the selected transport name.
    #[must_use]
    pub(super) fn name(&self) -> &str {
        match self {
            Self::WindowsNamedPipe { name } => name,
        }
    }

    /// Returns the transport limits selected by the Kernel composition.
    #[must_use]
    const fn limits() -> TransportLimits {
        TransportLimits {
            max_frame_bytes: eliot_protocol::MAX_FRAME_BYTES,
            queue_capacity: 128,
            queue_bytes: 8 * 1024 * 1024,
            control_reserve: 4,
            operation_timeout: Duration::from_secs(30),
        }
    }
}

impl KernelComposition {
    /// Returns the selected local IPC name for diagnostics and ready output.
    ///
    /// This is intentionally only a string snapshot.  It carries no
    /// transport or handshake authority and cannot be used to establish a
    /// session.
    #[must_use]
    pub fn ipc(&self) -> &str {
        self.ipc.name()
    }

    /// Returns the fixed transport limits for receive/send loops.
    ///
    /// The limits are diagnostic configuration only; session establishment
    /// remains owned by [`Self::bind_session`].
    #[must_use]
    pub const fn ipc_limits(&self) -> TransportLimits {
        IpcImplementation::limits()
    }

    /// Builds the immutable, bounded peer set for the production front door.
    /// Host and Eliotd are pinned to fresh OS-observed process bindings. The
    /// bridge is dynamic: its stable SID, image and file identity come from
    /// the promoted Host descriptor while PID/start/session are observed by
    /// the platform adapter for each pipe handle.
    #[cfg(windows)]
    fn front_door_peer_set_inner(
        &self,
        host_expectation: &NamedPipePeerExpectation,
    ) -> Result<NamedPipePeerSet, KernelBuildError> {
        if host_expectation.approved_process_binding().is_none()
            || host_expectation.is_dynamic_process()
        {
            return Err(KernelBuildError::Principal(
                "front-door Host expectation must contain one exact OS-observed process binding"
                    .to_owned(),
            ));
        }
        let host =
            NamedPipePeerProfile::new(NamedPipePeerKind::Host, host_expectation.clone(), None)
                .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        let mut entries = vec![host];

        let daemon_receipt = {
            let state = self.daemon_runtime.lock().map_err(|_| {
                KernelBuildError::Principal("daemon runtime lock poisoned".to_owned())
            })?;
            if matches!(
                state.status,
                DaemonRuntimeStatus::Running | DaemonRuntimeStatus::Ready
            ) {
                state.receipt.clone()
            } else {
                None
            }
        };
        if let Some(receipt) = daemon_receipt {
            receipt
                .validate()
                .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
            let physical = receipt.identity().physical();
            let observed = observe_named_pipe_peer_process(physical.process_id())
                .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
            if observed.start_time_100ns() != physical.start_time_100ns()
                || !observed
                    .image_path()
                    .eq_ignore_ascii_case(physical.image_path())
                || observed.executable_file_identity().is_none()
            {
                return Err(KernelBuildError::Principal(
                    "current eliotd receipt does not match fresh handle-bound process evidence"
                        .to_owned(),
                ));
            }
            let expectation = NamedPipePeerExpectation::new_with_process_binding(
                host_expectation.expected_sid().to_owned(),
                host_expectation.expected_session_id(),
                observed,
            )
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
            entries.push(
                NamedPipePeerProfile::new(NamedPipePeerKind::Eliotd, expectation, None)
                    .map_err(|error| KernelBuildError::Principal(error.to_string()))?,
            );
        }

        let bridge = self
            .agent_bridge_profile
            .lock()
            .map_err(|_| KernelBuildError::Principal("bridge profile lock poisoned".to_owned()))?
            .clone();
        if let Some(profile) = bridge {
            if self
                .agent_bridge_admission
                .as_ref()
                .is_some_and(|configured| configured != &profile.admission)
            {
                return Err(KernelBuildError::Principal(
                    "promoted bridge profile differs from retained Host admission".to_owned(),
                ));
            }
            let expectation = NamedPipePeerExpectation::new_for_dynamic_process(
                profile.admission.approved_user_sid.clone(),
                profile.admission.executable.as_str().to_owned(),
                WindowsFileIdentity {
                    volume_serial_number: profile
                        .admission
                        .executable_identity
                        .volume_serial_number,
                    file_index: profile.admission.executable_identity.file_index,
                },
            )
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
            entries.push(
                NamedPipePeerProfile::new(
                    NamedPipePeerKind::AgentBridge,
                    expectation,
                    Some(profile.admission.profile_id.as_str().to_owned()),
                )
                .map_err(|error| KernelBuildError::Principal(error.to_string()))?,
            );
        }
        NamedPipePeerSet::new(entries)
            .map_err(|error| KernelBuildError::Principal(error.to_string()))
    }

    /// Builds the immutable, bounded peer set for the production front door.
    ///
    /// Diagnostic wrapper around [`Self::front_door_peer_set_inner`]: emits
    /// one peer-set observation per attempt plus the single designated
    /// terminal on failure. No transport, authentication, or peer-set
    /// semantics change; sink failure never changes the result.
    #[cfg(windows)]
    pub fn front_door_peer_set(
        &self,
        host_expectation: &NamedPipePeerExpectation,
    ) -> Result<NamedPipePeerSet, KernelBuildError> {
        observe_front_door_session("kernel.front_door_peer_set_build", "attempt");
        let result = self.front_door_peer_set_inner(host_expectation);
        match &result {
            Ok(_) => {
                observe_front_door_session("kernel.front_door_peer_set_build", "success");
            }
            Err(error) => {
                observe_front_door_session("kernel.front_door_peer_set_build", "fenced");
                super::kernel_diagnostics::observe_terminal_error(peer_set_terminal_code(error));
            }
        }
        result
    }

    /// Returns a peer set paired with the exact revision observed before and
    /// after construction. Monotonic revisions make this snapshot safe from
    /// publishing a stale DACL under a newer revision during concurrent Host
    /// activation or eliotd lifecycle changes.
    #[cfg(windows)]
    fn front_door_peer_set_snapshot_inner(
        &self,
        host_expectation: &NamedPipePeerExpectation,
    ) -> Result<(u64, NamedPipePeerSet), KernelBuildError> {
        for _ in 0..8 {
            let before = self.agent_bridge_peer_set_revision();
            let peers = self.front_door_peer_set(host_expectation)?;
            let after = self.agent_bridge_peer_set_revision();
            if before == after {
                return Ok((after, peers));
            }
        }
        Err(KernelBuildError::Principal(
            "front-door peer set changed continuously during snapshot".to_owned(),
        ))
    }

    /// Returns a peer set paired with the exact revision observed before and
    /// after construction.
    ///
    /// Diagnostic wrapper: preserves the exact revision pair, emits the
    /// snapshot observation with the retained revision, and keeps one
    /// designated terminal per underlying failure. A peer-set propagation
    /// failure already emitted its terminal inside `front_door_peer_set`,
    /// so only the continuous-churn failure emits here.
    #[cfg(windows)]
    pub fn front_door_peer_set_snapshot(
        &self,
        host_expectation: &NamedPipePeerExpectation,
    ) -> Result<(u64, NamedPipePeerSet), KernelBuildError> {
        observe_front_door_session("kernel.front_door_peer_set_snapshot", "attempt");
        let result = self.front_door_peer_set_snapshot_inner(host_expectation);
        match &result {
            Ok((revision, _)) => {
                observe_peer_snapshot(*revision, "success");
            }
            Err(error) => {
                let is_churn = matches!(error, KernelBuildError::Principal(reason) if reason.contains("changed continuously"));
                if is_churn {
                    observe_peer_snapshot(self.agent_bridge_peer_set_revision(), "fenced");
                    super::kernel_diagnostics::observe_terminal_error(peer_set_terminal_code(
                        error,
                    ));
                } else {
                    observe_front_door_session("kernel.front_door_peer_set_snapshot", "fenced");
                }
            }
        }
        result
    }

    /// Binds an authenticated local peer to the selected principal/session.
    fn bind_session_inner(
        &self,
        connection_id: impl Into<String>,
        peer: PeerIdentity,
        client: &eliot_protocol::ClientHello,
    ) -> Result<HandshakeResult, eliot_ipc::TransportError> {
        let generation_poison = self
            .generation_poison
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        if generation_poison.is_some() {
            return Err(TransportError::SessionFenced);
        }
        #[cfg(windows)]
        if client.module_bridge_identity == AGENT_BRIDGE_MODULE_ID {
            // The bridge has a server-first transport owner. It must never
            // enter the legacy client-first Session/dispatch path.
            return Err(TransportError::SessionFenced);
        }
        #[cfg(windows)]
        if client.module_bridge_identity == ACTIVE_DAEMON_CALLER {
            self.validate_eliotd_peer(&peer, client)?;
        }
        if client.module_bridge_identity == DOCTOR_MODULE_ID {
            // The one-shot Doctor repair worker binds at session scope over
            // its already pipe-authenticated peer. Generation/epoch/artifact
            // are proven against live server policy inside; nothing
            // client-asserted becomes authority.
            return self.bind_doctor_session(connection_id, peer, client);
        }
        if client.module_bridge_identity == TESTD_MODULE_ID {
            // The one-shot testd admission worker binds at session scope over
            // its already pipe-authenticated peer. Generation/epoch/artifact
            // are proven against live server policy inside; nothing
            // client-asserted becomes authority.
            return self.bind_testd_session(connection_id, peer, client);
        }
        if client.module_bridge_identity == NATIVE_MODULE_ID {
            // The one-shot native-worker claim worker binds at session scope
            // over its already pipe-authenticated peer through the same
            // front-door session mechanism Doctor/Testd use: no dedicated
            // AuthenticatedNativeWorkerSession type exists on this base.
            // Generation/epoch/artifact are proven against live server
            // policy inside; nothing client-asserted becomes authority.
            return self.bind_native_worker_session(connection_id, peer, client);
        }
        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        Session::establish_with_server(connection_id, peer, client, &policy)
    }

    /// Binds an authenticated local peer to the selected principal/session.
    ///
    /// Diagnostic wrapper: decode/reject/accept stay distinct, acceptance
    /// never implies request admission, and exactly one terminal is emitted
    /// per failed handshake. Subordinate doctor/testd/native/eliotd
    /// validations emit info only; this wrapper owns the terminal.
    pub fn bind_session(
        &self,
        connection_id: impl Into<String>,
        peer: PeerIdentity,
        client: &eliot_protocol::ClientHello,
    ) -> Result<HandshakeResult, eliot_ipc::TransportError> {
        observe_front_door_session("kernel.front_door_handshake_decode", "attempt");
        let result = self.bind_session_inner(connection_id, peer, client);
        match &result {
            Ok(_) => {
                observe_front_door_session("kernel.front_door_handshake_accept", "success");
            }
            Err(error) => {
                observe_front_door_session("kernel.front_door_handshake_reject", "fenced");
                super::kernel_diagnostics::observe_terminal_error(transport_terminal_code(error));
            }
        }
        result
    }

    #[cfg(windows)]
    fn validate_eliotd_peer(
        &self,
        peer: &PeerIdentity,
        client: &eliot_protocol::ClientHello,
    ) -> Result<(), TransportError> {
        observe_front_door_session("kernel.front_door_eliotd_peer_validate", "attempt");
        let launch = self
            .active_daemon_launch()
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::SessionFenced)?;
        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        Self::validate_eliotd_client_binding(&launch, &policy, client)?;
        drop(policy);
        let peer_binding = peer
            .process_binding()
            .ok_or(TransportError::PeerIdentityUnavailable)?;
        let receipt = {
            let state = self
                .daemon_runtime
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            Self::published_daemon_receipt(&state)?
        };
        receipt
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let physical = receipt.identity().physical();
        // INTENDED EpochId shape (B→A→C): exact-tuple is_same_authority.
        if receipt.accepted_generation().get() != launch.generation.value()
            || !receipt
                .binding()
                .state_fence()
                .authority_epoch()
                .is_same_authority(&launch.authority_epoch)
            || receipt.identity().executable_sha256() != launch.executable_sha256
            || peer_binding.process_id() != physical.process_id()
            || peer_binding.start_time_100ns() != physical.start_time_100ns()
            || !peer_binding
                .image_path()
                .eq_ignore_ascii_case(physical.image_path())
        {
            return Err(TransportError::SessionFenced);
        }
        let observed = observe_named_pipe_peer_process_in_job(
            physical.executor_job_name(),
            physical.process_id(),
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let observed_binding = observed.process_binding();
        if observed_binding.process_id() != peer_binding.process_id()
            || observed_binding.start_time_100ns() != peer_binding.start_time_100ns()
            || observed_binding.start_time_100ns() != physical.start_time_100ns()
            || !observed_binding
                .image_path()
                .eq_ignore_ascii_case(physical.image_path())
            || !observed_binding
                .image_path()
                .eq_ignore_ascii_case(launch.executable.as_str())
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    #[cfg(windows)]
    pub(super) fn validate_eliotd_client_binding(
        launch: &EliotdLaunchDescriptor,
        policy: &ServerHandshakePolicy,
        client: &eliot_protocol::ClientHello,
    ) -> Result<(), TransportError> {
        if client.artifact_hash.as_str() != policy.module_generation.artifact_id.as_str()
            || client.module_generation.artifact_id.as_str() != launch.executable_sha256.as_str()
            || client.module_generation.generation != launch.generation
            || client.authority_epoch != launch.authority_epoch
            || client.launch_nonce.as_str() != launch.launch_nonce.as_str()
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    #[cfg(windows)]
    pub(super) fn published_daemon_receipt(
        state: &DaemonRuntimeState,
    ) -> Result<ProcessStartReceipt, TransportError> {
        match (&state.status, &state.receipt) {
            (DaemonRuntimeStatus::Launching, None) => Err(TransportError::PlanGap {
                dependency: ELIOTD_RECEIPT_PENDING_DEPENDENCY,
                reason: ELIOTD_RECEIPT_PENDING_REASON,
            }),
            (_, Some(receipt)) => Ok(receipt.clone()),
            _ => Err(TransportError::SessionFenced),
        }
    }

    /// Binds an authenticated Doctor repair worker to a least-privilege session.
    ///
    /// The presenting pipe peer was already authenticated by the listener's
    /// peer set; this entry proves the Doctor `ClientHello` generation-bound
    /// against the live server policy (exact generation, exact artifact,
    /// same-authority epoch, compatible fence) and then establishes the
    /// transport session. Capabilities are intersected down to the single
    /// admitted Doctor wire operation and effects are never session-bound:
    /// effect authority arrives only per attempt through a Kernel-minted
    /// recovery lease. The issued `ServerHello` advertises exactly that one
    /// operation; an invalid peer or epoch fences before any protected input.
    fn bind_doctor_session(
        &self,
        connection_id: impl Into<String>,
        peer: PeerIdentity,
        client: &eliot_protocol::ClientHello,
    ) -> Result<HandshakeResult, eliot_ipc::TransportError> {
        observe_front_door_session("kernel.front_door_doctor_bind", "attempt");
        let connection_id = connection_id.into();
        if connection_id.trim().is_empty() || connection_id.chars().any(char::is_control) {
            return Err(TransportError::SessionFenced);
        }
        peer.validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone();
        Self::validate_doctor_client_binding(&policy, client)?;
        let mut session = Session::establish(connection_id, peer, client, policy.protocol_range)?;
        session.capabilities = vec![DOCTOR_REPAIR_WIRE_ID.to_owned()];
        session
            .privacy_classes
            .retain(|class| policy.allowed_privacy_classes.contains(class));
        session.effects = Vec::new();
        let server_hello = eliot_protocol::ServerHello {
            selected_protocol: session.protocol_version,
            session_principal_binding: policy.session_principal_binding.clone(),
            allowed_capabilities: session.capabilities.clone(),
            allowed_effects: Vec::new(),
            config_snapshot: policy.config_snapshot.clone(),
            heartbeat_ms: policy.heartbeat_ms,
            control_channel: policy.control_channel.clone(),
            rejection_reason: None,
            authority_epoch: policy.module_generation.state_fence.authority_epoch.clone(),
        };
        server_hello
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(HandshakeResult {
            capabilities: session.capabilities.clone(),
            privacy_classes: session.privacy_classes.clone(),
            effects: Vec::new(),
            session,
            server_hello,
        })
    }

    /// Proves a Doctor `ClientHello` generation-bound against live server policy.
    ///
    /// Every doctor-asserted value is compared against the server-owned
    /// policy; nothing is copied into authority. The exact generation and
    /// artifact must match, the epoch must be the same authority, and the
    /// presented fence must be compatible with the live fence, so a stale or
    /// foreign generation can never bind.
    ///
    /// NOTE (bootstrap binding): there is no doctor launch descriptor on this
    /// base, so no caller launch nonce is adopted as authority here. Slice A
    /// binds the doctor bootstrap nonce to the Recovery Manifest record and
    /// extends this check; until then the live generation/epoch/artifact join
    /// above plus pipe authentication is the gate.
    fn validate_doctor_client_binding(
        policy: &ServerHandshakePolicy,
        client: &eliot_protocol::ClientHello,
    ) -> Result<(), TransportError> {
        if client.module_generation.generation != policy.module_generation.generation
            || client.module_generation.artifact_id != policy.module_generation.artifact_id
            || client.artifact_hash != policy.module_generation.artifact_id
            || !client
                .authority_epoch
                .is_same_authority(&policy.module_generation.state_fence.authority_epoch)
            || !client
                .module_generation
                .state_fence
                .is_compatible_with(&policy.module_generation.state_fence)
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    /// Binds an authenticated testd admission worker to a least-privilege session.
    ///
    /// The presenting pipe peer was already authenticated by the listener's
    /// peer set; this entry proves the testd `ClientHello` generation-bound
    /// against the live server policy (exact generation, exact artifact,
    /// same-authority epoch, compatible fence) and then establishes the
    /// transport session. Capabilities are intersected down to the single
    /// admitted testd wire operation and effects are never session-bound:
    /// execution authority arrives only per job through a Kernel-minted
    /// admission. The issued `ServerHello` advertises exactly that one
    /// operation; an invalid peer or epoch fences before any protected input.
    fn bind_testd_session(
        &self,
        connection_id: impl Into<String>,
        peer: PeerIdentity,
        client: &eliot_protocol::ClientHello,
    ) -> Result<HandshakeResult, eliot_ipc::TransportError> {
        observe_front_door_session("kernel.front_door_testd_bind", "attempt");
        let connection_id = connection_id.into();
        if connection_id.trim().is_empty() || connection_id.chars().any(char::is_control) {
            return Err(TransportError::SessionFenced);
        }
        peer.validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone();
        Self::validate_testd_client_binding(&policy, client)?;
        let mut session = Session::establish(connection_id, peer, client, policy.protocol_range)?;
        session.capabilities = vec![TESTD_ADMISSION_WIRE_ID.to_owned()];
        session
            .privacy_classes
            .retain(|class| policy.allowed_privacy_classes.contains(class));
        session.effects = Vec::new();
        let server_hello = eliot_protocol::ServerHello {
            selected_protocol: session.protocol_version,
            session_principal_binding: policy.session_principal_binding.clone(),
            allowed_capabilities: session.capabilities.clone(),
            allowed_effects: Vec::new(),
            config_snapshot: policy.config_snapshot.clone(),
            heartbeat_ms: policy.heartbeat_ms,
            control_channel: policy.control_channel.clone(),
            rejection_reason: None,
            authority_epoch: policy.module_generation.state_fence.authority_epoch.clone(),
        };
        server_hello
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(HandshakeResult {
            capabilities: session.capabilities.clone(),
            privacy_classes: session.privacy_classes.clone(),
            effects: Vec::new(),
            session,
            server_hello,
        })
    }

    /// Proves a testd `ClientHello` generation-bound against live server policy.
    ///
    /// Every testd-asserted value is compared against the server-owned
    /// policy; nothing is copied into authority. The exact generation and
    /// artifact must match, the epoch must be the same authority, and the
    /// presented fence must be compatible with the live fence, so a stale or
    /// foreign generation can never bind.
    ///
    /// NOTE (bootstrap binding): there is no testd launch descriptor on this
    /// base, so no caller launch nonce is adopted as authority here. A later
    /// slice binds the testd bootstrap nonce to its durable record and
    /// extends this check; until then the live generation/epoch/artifact join
    /// above plus pipe authentication is the gate.
    fn validate_testd_client_binding(
        policy: &ServerHandshakePolicy,
        client: &eliot_protocol::ClientHello,
    ) -> Result<(), TransportError> {
        if client.module_generation.generation != policy.module_generation.generation
            || client.module_generation.artifact_id != policy.module_generation.artifact_id
            || client.artifact_hash != policy.module_generation.artifact_id
            || !client
                .authority_epoch
                .is_same_authority(&policy.module_generation.state_fence.authority_epoch)
            || !client
                .module_generation
                .state_fence
                .is_compatible_with(&policy.module_generation.state_fence)
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    /// Binds an authenticated native-worker claim worker to a
    /// least-privilege session.
    ///
    /// Reuses the exact Doctor/Testd front-door session mechanism: the
    /// presenting pipe peer was already authenticated by the listener's peer
    /// set, and this entry proves the native-worker `ClientHello`
    /// generation-bound against the live server policy (exact generation,
    /// exact artifact, same-authority epoch, compatible fence) before
    /// establishing the transport session. Capabilities are intersected down
    /// to the single admitted native-worker claim wire
    /// (`eliot.kernel.native-worker-claim`) and effects are never
    /// session-bound: execution authority arrives only per claim through a
    /// Kernel-minted admission. No dedicated
    /// `AuthenticatedNativeWorkerSession` type exists on this base; this is
    /// the same session shape Doctor/Testd use.
    fn bind_native_worker_session(
        &self,
        connection_id: impl Into<String>,
        peer: PeerIdentity,
        client: &eliot_protocol::ClientHello,
    ) -> Result<HandshakeResult, eliot_ipc::TransportError> {
        observe_front_door_session("kernel.front_door_native_worker_bind", "attempt");
        let connection_id = connection_id.into();
        if connection_id.trim().is_empty() || connection_id.chars().any(char::is_control) {
            return Err(TransportError::SessionFenced);
        }
        peer.validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone();
        Self::validate_native_worker_client_binding(&policy, client)?;
        let mut session = Session::establish(connection_id, peer, client, policy.protocol_range)?;
        session.capabilities = vec![NATIVE_WORKER_CLAIM_WIRE_ID.to_owned()];
        session
            .privacy_classes
            .retain(|class| policy.allowed_privacy_classes.contains(class));
        session.effects = Vec::new();
        let server_hello = eliot_protocol::ServerHello {
            selected_protocol: session.protocol_version,
            session_principal_binding: policy.session_principal_binding.clone(),
            allowed_capabilities: session.capabilities.clone(),
            allowed_effects: Vec::new(),
            config_snapshot: policy.config_snapshot.clone(),
            heartbeat_ms: policy.heartbeat_ms,
            control_channel: policy.control_channel.clone(),
            rejection_reason: None,
            authority_epoch: policy.module_generation.state_fence.authority_epoch.clone(),
        };
        server_hello
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(HandshakeResult {
            capabilities: session.capabilities.clone(),
            privacy_classes: session.privacy_classes.clone(),
            effects: Vec::new(),
            session,
            server_hello,
        })
    }

    /// Proves a native-worker `ClientHello` generation-bound against live
    /// server policy.
    ///
    /// Every native-worker-asserted value is compared against the
    /// server-owned policy; nothing is copied into authority. The exact
    /// generation and artifact must match, the epoch must be the same
    /// authority, and the presented fence must be compatible with the live
    /// fence, so a stale or foreign generation can never bind.
    ///
    /// NOTE (bootstrap binding): there is no native-worker launch descriptor
    /// on this base, so no caller launch nonce is adopted as authority here.
    /// A later slice binds the native-worker bootstrap nonce to its durable
    /// claim record and extends this check; until then the live
    /// generation/epoch/artifact join above plus pipe authentication is the
    /// gate — the same shape Doctor/Testd use.
    fn validate_native_worker_client_binding(
        policy: &ServerHandshakePolicy,
        client: &eliot_protocol::ClientHello,
    ) -> Result<(), TransportError> {
        if client.module_generation.generation != policy.module_generation.generation
            || client.module_generation.artifact_id != policy.module_generation.artifact_id
            || client.artifact_hash != policy.module_generation.artifact_id
            || !client
                .authority_epoch
                .is_same_authority(&policy.module_generation.state_fence.authority_epoch)
            || !client
                .module_generation
                .state_fence
                .is_compatible_with(&policy.module_generation.state_fence)
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }
}
