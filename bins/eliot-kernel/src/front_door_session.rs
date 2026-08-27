use super::*;

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
    pub fn front_door_peer_set(
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

    /// Returns a peer set paired with the exact revision observed before and
    /// after construction. Monotonic revisions make this snapshot safe from
    /// publishing a stale DACL under a newer revision during concurrent Host
    /// activation or eliotd lifecycle changes.
    #[cfg(windows)]
    pub fn front_door_peer_set_snapshot(
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

    /// Binds an authenticated local peer to the selected principal/session.
    pub fn bind_session(
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
        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        Session::establish_with_server(connection_id, peer, client, &policy)
    }

    #[cfg(windows)]
    fn validate_eliotd_peer(
        &self,
        peer: &PeerIdentity,
        client: &eliot_protocol::ClientHello,
    ) -> Result<(), TransportError> {
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
        if receipt.accepted_generation().get() != launch.generation.value()
            || receipt.binding().state_fence().authority_epoch() != launch.authority_epoch.value()
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
}
