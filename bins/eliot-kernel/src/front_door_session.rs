//! Kernel front-door session binding and peer identity validation.
//!
//! Traceability: Architecture A2.3, A12.2, A12.3, A13.2;
//! principles ARCH-AUTH-01, ARCH-SEC-01, ARCH-SEC-02.
//! Implementation I1.2, I1.8, I1.12, I7.1, I7.3, I7.5, I7.14, I15.2, P.3, I2.23.
//!
//! This module owns the Windows-first transport selection and limits,
//! authenticated peer-set construction/snapshot, and Kernel-side session
//! binding. It validates generation-bound `eliotd` identity and fails closed
//! on poisoned or stale state; it does not dispatch frames, grant semantic
//! authority, or persist canonical transitions.
//!
//! It is also where the I1.12 compatibility envelope is PUBLISHED on the one
//! process boundary that requires it: `front_door_handshake_policy` adds the
//! five remaining envelope items to a per-session CLONE of the front-door
//! policy when - and only when - the caller is the daemon identity. The stored
//! policy object is deliberately left untouched because its whole-object digest
//! is pinned elsewhere.

use super::user_broker_registration_route::{
    USER_BROKER_BIND_OPERATOR_SESSION_TOKEN_OPERATION, USER_BROKER_FENCE_OPERATION,
    USER_BROKER_HEARTBEAT_OPERATION, USER_BROKER_REGISTER_OPERATION,
    USER_BROKER_VALIDATE_NATIVE_RESOURCE_SELECTION_CURRENT_OPERATION,
};
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
        eliot_ipc::TransportError::LegacyCorrelationUnresolved => "legacy_correlation_unresolved",
        eliot_ipc::TransportError::Cancelled => "cancelled",
        eliot_ipc::TransportError::Backpressure
        | eliot_ipc::TransportError::AttributedBackpressure(_) => "backpressure",
        eliot_ipc::TransportError::InvalidLimits => "invalid_limits",
        eliot_ipc::TransportError::InvalidPipeName => "invalid_pipe_name",
        eliot_ipc::TransportError::RegistryFull => "registry_full",
        eliot_ipc::TransportError::Io(_) => "transport_io",
        eliot_ipc::TransportError::PlanGap { .. } => "plan_gap",
        eliot_ipc::TransportError::Protocol(_) => "protocol",
    }
}

#[derive(Default)]
pub(super) struct DaemonSessionBindingAuditEvidence {
    pub(super) refusal_cause: Option<&'static str>,
    pub(super) owner_launch: Option<EliotdLaunchDescriptor>,
    pub(super) owner_process_receipt: Option<ProcessStartReceipt>,
}

impl DaemonSessionBindingAuditEvidence {
    fn refuse(&mut self, client: &eliot_protocol::ClientHello, cause: &'static str) {
        if client.module_bridge_identity == ACTIVE_DAEMON_CALLER && self.refusal_cause.is_none() {
            self.refusal_cause = Some(cause);
        }
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
/// NOTE (platform boundary): the OS pipe peer set admits Host, Eliotd,
/// `AgentBridge`, Watchdog, and the installer-pinned User Broker roles.
/// Doctor remains bound at session scope over its already-authenticated peer;
/// invalid peer or epoch gets no protected input.
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
/// NOTE (front-door reuse): the Watchdog submits its retained `watchdog.redb`
/// intent spool through the same closed front-door frame route every other
/// local peer uses, so it needs no second pipe family and no server-first
/// transport owner. It is admitted as its own peer role and bound to its own
/// least-privilege session below; see
/// [`KernelComposition::bind_watchdog_session`].
pub(crate) const NATIVE_MODULE_ID: &str = "eliot-native-worker";

/// Stable module identity of the independent supervision service.
///
/// The Watchdog never self-asserts authority through this string:
/// [`KernelComposition::bind_session`] admits it only over an already
/// pipe-authenticated peer role whose process identity the platform adapter
/// observed from the live SCM service, and only after
/// [`KernelComposition::validate_watchdog_client_binding`] proves its
/// `ClientHello` generation-bound against the live server policy.
///
/// NOTE (front-door reuse): like Doctor/Testd, the Watchdog has no
/// server-first transport owner and no dedicated session bootstrap, so it
/// rides the ordinary client-first handshake and the same admitted frame
/// gateway. It requires no agent-bridge Session, no bridge activation, and no
/// bridge profile.
pub(crate) const WATCHDOG_MODULE_ID: &str = "eliot-watchdog";

/// Builds the front-door `Watchdog` peer role, or `None` when no Watchdog
/// service process is currently observable.
///
/// The Watchdog is an SCM-owned sibling of the Host service, so the Kernel
/// holds no launch receipt for it and never receives one. Its process identity
/// is therefore taken from the process the platform adapter observes live from
/// the canonical SCM service, and its account SID is resolved from the same
/// canonical service name. Both facts come from the operating system, never
/// from a caller, a request, or a Host-injected value; the role carries no
/// static profile identity and is admitted at exactly the strength the Host
/// and `eliotd` roles get.
///
/// A Watchdog that is not currently running contributes no role at all. That
/// leaves the peer set unable to select it, so such a connection is refused
/// closed; it is never replaced by a broader Host or bridge role, and a
/// transient observation failure is never treated as an admission.
///
/// # Errors
///
/// Returns [`KernelBuildError::Principal`] when the Watchdog service process is
/// observable but its account SID cannot be resolved, or when the observed
/// process and the resolved SID cannot form a valid static expectation.
#[cfg(windows)]
fn front_door_watchdog_peer_profile(
    expected_session_id: u32,
) -> Result<Option<NamedPipePeerProfile>, KernelBuildError> {
    let Ok(observed) = observe_running_eliot_watchdog_process() else {
        return Ok(None);
    };
    let sid = resolve_service_sid(ELIOT_WATCHDOG_SERVICE_NAME)
        .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
    let expectation =
        NamedPipePeerExpectation::new_with_process_binding(sid, expected_session_id, observed)
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
    NamedPipePeerProfile::new(NamedPipePeerKind::Watchdog, expectation, None)
        .map(Some)
        .map_err(|error| KernelBuildError::Principal(error.to_string()))
}

/// Selects the handshake policy ONE session hands to
/// [`Session::establish_with_server`].
///
/// I1.12 (#1968) requires every process handshake to exchange the whole
/// compatibility envelope, and this is the producer half of it for the one
/// caller that requires it. `eliot-ipc` cannot publish the envelope itself:
/// that crate does not depend on `eliot-kernel-core`, so the envelope's owner
/// crate is absent from its closure, and `Session::establish_with_server` only
/// copies `policy.config_snapshot` into the `ServerHello` it builds. This binary
/// holds both the owner crate and [`ACTIVE_DAEMON_CALLER`], so the envelope is
/// projected here instead.
///
/// # The five values are this Kernel's own compiled identity
///
/// Nothing here is derived from the peer, and nothing is restated. All five are
/// read from their owners in `eliot-kernel-core` through the ONE durable-state
/// derivation this binary already gates its own boundaries with,
/// `super::compatibility_gate::durable_compatibility_state`:
///
/// - `contract_set_digest`, `canonical_format_range` and
///   `architecture_source_digest` are that state's own accessors, and it
///   derives the digest from `super::frame_dispatch::runtime_contract_set_digest`
///   over the same four public contract identities (`eliot-kernel-core`,
///   `eliot-kernel-service`, `eliot-protocol`, `eliot-runtime-contracts`) the
///   owner defines the digest over. No argument list is spelled here.
/// - `normative_pair_receipt` is the owner's `NormativePairReceipt` over that
///   same digest, projected through its own `architecture_source_digest()` and
///   `seal_tag()` accessors, so the published shape is the owner's shape.
/// - `state_migration_class` is the owner's `StateMigrationClass` value this
///   Kernel's durable compatibility state declares - the same declaration
///   `compatibility_gate::durable_compatibility_state` makes, not a second
///   spelling of it.
///
/// # The STORED policy is deliberately untouched, and why
///
/// `super::agent_bridge::begin_agent_bridge_inner` pins the WHOLE stored policy
/// object: it hashes `sha256_json(&kernel_policy.config_snapshot)` and compares
/// that with `declaration.expected_kernel_config_snapshot_sha256`, whose in-tree
/// producers (`eliot-installation`'s `agent_bridge_profile` and
/// `package_planner`) hash a literal naming exactly six keys (`service`,
/// `protocol`, `generation`, `authority_epoch`, `artifact_digest`,
/// `protected_snapshot_digest`). Inserting one key into the stored object
/// changes those bytes and refuses six binaries at activation. This function
/// therefore extends a per-session CLONE only, and the stored object keeps
/// exactly the six keys `composition_bootstrap::front_door_config_snapshot`
/// builds. That asymmetry is the whole reason the producer lives beside the
/// session rather than inside the policy builder.
///
/// # A missing digest-pinned key is NOT refused here, and that is stated rather
/// # than assumed
///
/// The stored object is supposed to name exactly six keys, but nothing on this
/// path verifies that: `composition_bootstrap::front_door_config_snapshot` OMITS
/// `artifact_digest` and `protected_snapshot_digest` when it has no value for
/// them (it takes both as `Option`), and `Session::establish_with_server`
/// publishes whatever object the policy holds without inspecting its keys. So a
/// policy object missing one of the six is published to the daemon today, with
/// the five envelope keys added on top. This function neither invents the
/// missing key nor refuses the session, because adding that gate is a separate
/// decision from publishing the envelope and would fence every Kernel that
/// currently starts without an artifact or protected-snapshot digest. It is
/// recorded here instead: the refusal that such an object actually meets is the
/// receiver's - `eliotd`'s `KernelSnapshotWire` and `eliot-cli`'s
/// `KernelConfigSnapshot` both declare these keys as REQUIRED, and the
/// agent-bridge whole-object digest refuses it too. The
/// `a_policy_missing_a_digest_pinned_key_is_published_not_repaired` test pins
/// that measured state.
///
/// # Why only the daemon caller receives the five keys
///
/// The extension is gated on [`ACTIVE_DAEMON_CALLER`] alone. `eliotd` is the one
/// receiver that REQUIRES the five items - it refuses their absence by name
/// (`bins/eliotd/src/daemon_kernel_client/handshake.rs`,
/// `admit_kernel_peer_compatibility`) - and two other consumers decode this same
/// `ServerHello.config_snapshot` under `#[serde(deny_unknown_fields)]` against
/// their own closed key set: the operator CLI (`crates/surfaces/eliot-cli`) and
/// the governed research client (`bins/eliot-mod-research`). For those two an
/// added key is a refusal, not a widened contract, so every non-daemon caller
/// of [`Session::establish_with_server`] keeps receiving the object with exactly
/// its original keys.
///
/// # The seal tag is not an independent seal
///
/// `eliot_kernel_core::expected_seal_tag` is unkeyed SHA-256 over published
/// constants, so the TAG half of the published receipt is not an independent
/// seal: it proves only that its holder can compute a published hash, and no
/// external seal issuer exists in this repository. It is still published because
/// it is the only constraint the receiver has on the presented tag. The DIGEST
/// half is what binds the receipt to a peer at all: a receiver compares the
/// presented `architecture_source_digest` against its OWN compiled
/// `CURRENT_ARCHITECTURE_SOURCE_DIGEST`, which is an operand the peer never
/// supplied.
///
/// # Errors
///
/// Returns a stable refusal cause when this build cannot derive its own envelope
/// (the durable compatibility state or the receipt does not construct) or when
/// the stored snapshot is not a JSON object the envelope could be added to. Both
/// are fences: a daemon session that cannot present a full envelope is refused
/// rather than admitted with a partial one.
fn front_door_handshake_policy(
    stored: &ServerHandshakePolicy,
    client: &eliot_protocol::ClientHello,
) -> Result<ServerHandshakePolicy, &'static str> {
    let mut policy = stored.clone();
    if client.module_bridge_identity != ACTIVE_DAEMON_CALLER {
        return Ok(policy);
    }
    let durable = super::compatibility_gate::durable_compatibility_state(
        &policy.module_generation.state_fence.authority_epoch,
    )
    .map_err(|_| "kernel.compatibility_envelope_underivable")?;
    let normative_pair_receipt = eliot_kernel_core::NormativePairReceipt::new(
        durable.architecture_source_digest(),
        eliot_kernel_core::expected_seal_tag(durable.architecture_source_digest()),
    )
    .map_err(|_| "kernel.compatibility_envelope_underivable")?;
    let serde_json::Value::Object(mut config_snapshot) = policy.config_snapshot else {
        return Err("kernel.compatibility_snapshot_not_an_object");
    };
    config_snapshot.insert(
        "contract_set_digest".to_owned(),
        serde_json::json!(durable.contract_set_digest()),
    );
    config_snapshot.insert(
        "canonical_format_range".to_owned(),
        serde_json::json!(durable.canonical_format_range()),
    );
    config_snapshot.insert(
        "architecture_source_digest".to_owned(),
        serde_json::json!(durable.architecture_source_digest()),
    );
    config_snapshot.insert(
        "normative_pair_receipt".to_owned(),
        serde_json::json!({
            "architecture_source_digest": normative_pair_receipt.architecture_source_digest(),
            "seal_tag": normative_pair_receipt.seal_tag(),
        }),
    );
    config_snapshot.insert(
        "state_migration_class".to_owned(),
        serde_json::json!(durable.migration_class()),
    );
    policy.config_snapshot = serde_json::Value::Object(config_snapshot);
    Ok(policy)
}

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

    /// Returns the in-flight byte bound this transport actually registers.
    ///
    /// The I12.14 hot-spine bind reads it from here rather than from the
    /// declaration, so the running build stays the authoritative side of the
    /// comparison: a manifest that names a different byte bound is refused.
    #[must_use]
    pub(super) const fn registered_queue_bytes() -> usize {
        Self::limits().queue_bytes
    }

    /// Returns the single-frame byte bound this transport actually registers.
    #[must_use]
    pub(super) const fn registered_frame_bytes() -> usize {
        Self::limits().max_frame_bytes
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
    /// the platform adapter for each pipe handle. The Watchdog sibling service
    /// is pinned the same way Host and `eliotd` are: the platform adapter
    /// observes its live SCM-reported process, so no Host-injected, client
    /// supplied, or request-supplied value enters its expectation. User
    /// Broker is also dynamic, but its exact image and file identity come from
    /// Host's installer-pinned path/digest and its token must prove enabled
    /// INTERACTIVE membership plus an active OS-observed session.
    #[cfg(windows)]
    fn user_broker_peer_profile(&self) -> Result<Option<NamedPipePeerProfile>, KernelBuildError> {
        let (Some(path), Some(digest)) = (
            self.user_broker_executable_path.as_deref(),
            self.user_broker_artifact_sha256.as_deref(),
        ) else {
            return Ok(None);
        };
        let (pinned_path, file_identity) =
            eliot_platform_windows::validate_pinned_artifact_with_identity(path, digest)
                .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        let expectation = NamedPipePeerExpectation::new_for_interactive_dynamic_process(
            pinned_path.to_string_lossy().into_owned(),
            WindowsFileIdentity {
                volume_serial_number: file_identity.volume_serial_number,
                file_index: file_identity.file_index,
            },
        )
        .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        NamedPipePeerProfile::new(NamedPipePeerKind::UserBroker, expectation, None)
            .map(Some)
            .map_err(|error| KernelBuildError::Principal(error.to_string()))
    }

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

        if let Some(profile) = self.user_broker_peer_profile()? {
            entries.push(profile);
        }

        // The Watchdog is an SCM-owned sibling of the Host service, so the
        // Kernel holds no launch receipt for it and never receives one.
        if let Some(profile) =
            front_door_watchdog_peer_profile(host_expectation.expected_session_id())?
        {
            entries.push(profile);
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
        let Ok(_transition) = self.agent_bridge_transition_read() else {
            let error =
                KernelBuildError::Principal("bridge profile transition lock poisoned".to_owned());
            observe_front_door_session("kernel.front_door_peer_set_build", "fenced");
            super::kernel_diagnostics::observe_terminal_error(peer_set_terminal_code(&error));
            return Err(error);
        };
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
            // The public snapshot boundary already owns the transition read
            // guard. Re-entering `front_door_peer_set` here could block on a
            // queued writer because `std::sync::RwLock` does not guarantee
            // recursive reader acquisition. Keep the whole retry loop under
            // that one guard and call the uninstrumented builder directly.
            let peers = self.front_door_peer_set_inner(host_expectation)?;
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
    /// Diagnostic wrapper: preserves the exact revision pair and emits the
    /// snapshot observation with the retained revision. Observation only:
    /// the single designated terminal for a failed snapshot is `exit_error`
    /// (`COMPOSITION_FAILURE`), so this wrapper never terminalises and one
    /// failed snapshot yields exactly one terminal record. The snapshot path
    /// calls the uninstrumented builder while it owns the transition read
    /// guard.
    #[cfg(windows)]
    pub fn front_door_peer_set_snapshot(
        &self,
        host_expectation: &NamedPipePeerExpectation,
    ) -> Result<(u64, NamedPipePeerSet), KernelBuildError> {
        let Ok(_transition) = self.agent_bridge_transition_read() else {
            let error =
                KernelBuildError::Principal("bridge profile transition lock poisoned".to_owned());
            // F-LOG-KERNEL-1 (#897 W5): info-only correlate. The single
            // designated terminal for this startup failure is `exit_error`
            // (`COMPOSITION_FAILURE`); the sibling startup bind in
            // `front_door_listener.rs` terminalises nothing for the same
            // reason.
            observe_front_door_session("kernel.front_door_peer_set_snapshot", "fenced");
            return Err(error);
        };
        observe_front_door_session("kernel.front_door_peer_set_snapshot", "attempt");
        let result = self.front_door_peer_set_snapshot_inner(host_expectation);
        match &result {
            Ok((revision, _)) => {
                observe_peer_snapshot(*revision, "success");
            }
            Err(error) => {
                // F-LOG-KERNEL-1 (#897 W5): info-only correlate for builder
                // failures and churn alike; `exit_error` owns the single
                // designated terminal, so no terminal is emitted here.
                let is_churn = matches!(error, KernelBuildError::Principal(reason) if reason.contains("changed continuously"));
                if is_churn {
                    observe_peer_snapshot(self.agent_bridge_peer_set_revision(), "fenced");
                } else {
                    observe_front_door_session("kernel.front_door_peer_set_snapshot", "fenced");
                }
            }
        }
        result
    }

    /// Binds the Host `UserAutomation` owner to the exact live Kernel
    /// activation contour.
    ///
    /// The named-pipe peer set authenticates the presenting Host process. The
    /// retained candidate, activation receipt, and ready receipt then bind
    /// the `ClientHello` to the current Kernel generation and activation
    /// receipt digest. This session advertises only the requester-side
    /// Dreamer capability; no caller payload can widen it.
    #[cfg(windows)]
    #[allow(clippy::too_many_lines)]
    fn bind_host_user_automation_session(
        &self,
        connection_id: impl Into<String>,
        peer: PeerIdentity,
        client: &eliot_protocol::ClientHello,
    ) -> Result<HandshakeResult, eliot_ipc::TransportError> {
        observe_front_door_session("kernel.front_door_host_user_automation_bind", "attempt");
        let connection_id = connection_id.into();
        if connection_id.trim().is_empty() || connection_id.chars().any(char::is_control) {
            return Err(TransportError::SessionFenced);
        }
        peer.validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;

        let (candidate, activation, ready) = {
            let service = self
                .service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            if service.state() != KernelServiceState::Ready {
                return Err(TransportError::SessionFenced);
            }
            let candidate = service
                .candidate_binding()
                .cloned()
                .ok_or(TransportError::SessionFenced)?;
            let activation = service
                .activation_receipt()
                .cloned()
                .ok_or(TransportError::SessionFenced)?;
            let ready = service
                .ready_receipt()
                .cloned()
                .ok_or(TransportError::SessionFenced)?;
            (candidate, activation, ready)
        };
        candidate
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if activation.candidate_binding_digest
            != candidate
                .compute_digest()
                .map_err(|_| TransportError::SessionFenced)?
            || activation.authority_epoch != candidate.kernel_epoch
        {
            return Err(TransportError::SessionFenced);
        }
        ready
            .validate(&candidate, &activation)
            .map_err(|_| TransportError::SessionFenced)?;

        let candidate_digest = candidate
            .compute_digest()
            .map_err(|_| TransportError::SessionFenced)?;
        let activation_digest = sha256_hex(
            &canonical_json_bytes(&activation).map_err(|_| TransportError::SessionFenced)?,
        );
        let expected_fence = StateFence::new(candidate.kernel_epoch.clone(), activation.generation);
        let peer_binding = peer
            .process_binding()
            .ok_or(TransportError::PeerIdentityUnavailable)?;
        if peer_binding.process_id() != candidate.host_process.process_id
            || peer_binding.start_time_100ns() != candidate.host_process.start_time_100ns
            || !peer_binding
                .image_path()
                .eq_ignore_ascii_case(&candidate.host_process.image_path)
        {
            return Err(TransportError::SessionFenced);
        }
        if client.module_bridge_identity != USER_AUTOMATION_KERNEL_MODULE_ID
            || client.artifact_hash.as_str() != candidate.artifact_hash.as_str()
            || client.module_generation.module_id.as_str() != USER_AUTOMATION_KERNEL_MODULE_ID
            || client.module_generation.generation != activation.generation
            || client.module_generation.artifact_id.as_str() != candidate.artifact_hash.as_str()
            || client.module_generation.state != ModuleGenerationState::Active
            || client.module_generation.state_fence != expected_fence
            || client.authority_epoch != candidate.kernel_epoch
            || client.launch_nonce != activation_digest
            || client.capabilities.len() != 1
            || client.capabilities[0] != USER_AUTOMATION_KERNEL_CAPABILITY
            || client.module_contract.required_capabilities.len() != 1
            || client.module_contract.required_capabilities[0] != USER_AUTOMATION_KERNEL_CAPABILITY
        {
            return Err(TransportError::SessionFenced);
        }

        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone();
        if !policy
            .allowed_capabilities
            .iter()
            .any(|capability| capability == USER_AUTOMATION_KERNEL_CAPABILITY)
            || !policy
                .allowed_privacy_classes
                .iter()
                .any(|privacy| privacy == USER_AUTOMATION_KERNEL_PRIVACY_CLASS)
        {
            return Err(TransportError::SessionFenced);
        }
        // `allowed_effects` belongs to the shared daemon policy.  This
        // server-authored special session deliberately projects no effects;
        // its Submit request is admitted separately by the typed Dreamer
        // route and its own canonical request authority.  Do not inherit the
        // daemon effect set merely because both routes use one front door.
        let mut session =
            Session::establish(connection_id.clone(), peer, client, policy.protocol_range)?;
        session
            .capabilities
            .retain(|capability| policy.allowed_capabilities.contains(capability));
        session
            .privacy_classes
            .retain(|privacy| policy.allowed_privacy_classes.contains(privacy));
        if session.capabilities != vec![USER_AUTOMATION_KERNEL_CAPABILITY.to_owned()]
            || session.privacy_classes != vec![USER_AUTOMATION_KERNEL_PRIVACY_CLASS.to_owned()]
        {
            return Err(TransportError::SessionFenced);
        }
        session.effects.clear();
        let config_snapshot = serde_json::json!({
            "policy": policy.config_snapshot,
            "eliot.user_automation": {
                "capability": USER_AUTOMATION_KERNEL_CAPABILITY,
                "privacy_classes": session.privacy_classes.clone(),
                "effects": session.effects.clone(),
                "candidate_binding_sha256": candidate_digest,
                "activation_receipt_sha256": activation_digest,
                "connection_id": connection_id,
            },
        });
        let server_hello = eliot_protocol::ServerHello {
            selected_protocol: session.protocol_version,
            session_principal_binding: USER_AUTOMATION_KERNEL_PRINCIPAL_BINDING.to_owned(),
            allowed_capabilities: session.capabilities.clone(),
            allowed_effects: Vec::new(),
            config_snapshot,
            heartbeat_ms: policy.heartbeat_ms,
            control_channel: policy.control_channel,
            rejection_reason: None,
            authority_epoch: candidate.kernel_epoch,
        };
        server_hello
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        observe_front_door_session("kernel.front_door_host_user_automation_bind", "success");
        Ok(HandshakeResult {
            capabilities: session.capabilities.clone(),
            privacy_classes: session.privacy_classes.clone(),
            effects: Vec::new(),
            session,
            server_hello,
        })
    }

    /// Binds an authenticated local peer to the selected principal/session.
    fn bind_session_inner(
        &self,
        connection_id: impl Into<String>,
        peer: PeerIdentity,
        client: &eliot_protocol::ClientHello,
        audit_evidence: &mut DaemonSessionBindingAuditEvidence,
    ) -> Result<HandshakeResult, eliot_ipc::TransportError> {
        // I1.13 / #1972: the shared Kernel-unavailability guard runs before
        // any Session is established, so an unavailable Kernel issues no new
        // Session on this front door. The availability value is this
        // composition's own live observation (see
        // `KernelComposition::observed_kernel_availability`), and the refusal
        // reuses this path's existing terminal rather than a second code.
        crate::kernel_unavailability::admit_new_session(self.observed_kernel_availability())
            .map_err(|_denial| TransportError::SessionFenced)?;
        let Ok(generation_poison) = self.generation_poison.lock() else {
            audit_evidence.refuse(client, "kernel.generation_poison_state_unavailable");
            return Err(TransportError::SessionFenced);
        };
        if generation_poison.is_some() {
            audit_evidence.refuse(client, "kernel.generation_poisoned");
            return Err(TransportError::SessionFenced);
        }
        #[cfg(windows)]
        if client.module_bridge_identity == AGENT_BRIDGE_MODULE_ID {
            // The bridge has a server-first transport owner. It must never
            // enter the legacy client-first Session/dispatch path.
            return Err(TransportError::SessionFenced);
        }
        #[cfg(windows)]
        if client.module_bridge_identity == "eliot-user-broker" {
            // User Broker must enter through its OS-selected role binder, not
            // by asserting a module identity in a generic client hello. That
            // owner-issued launch binding is not available yet.
            return Err(TransportError::SessionFenced);
        }
        #[cfg(windows)]
        if client.module_bridge_identity == USER_AUTOMATION_KERNEL_MODULE_ID {
            return self.bind_host_user_automation_session(connection_id, peer, client);
        }
        #[cfg(windows)]
        if client.module_bridge_identity == ACTIVE_DAEMON_CALLER {
            self.validate_eliotd_peer(&peer, client, audit_evidence)?;
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
        if client.module_bridge_identity == WATCHDOG_MODULE_ID {
            // The independent supervision service binds at session scope over
            // its already pipe-authenticated Watchdog peer role. It presents
            // only its own retained `watchdog.redb` intent spool through the
            // closed `watchdog_intent_submit` frame route, and it needs no
            // agent-bridge Session, bridge activation, or bridge profile: a
            // Watchdog has none of those, and demanding them is exactly what
            // previously left the spool with no transport at all.
            // Generation/epoch/artifact are proven against live server policy
            // inside; nothing client-asserted becomes authority, and the
            // fenced intent route still resolves every submission against the
            // retained supervision lease the Kernel itself holds.
            return self.bind_watchdog_session(connection_id, peer, client);
        }
        if client.module_bridge_identity != ACTIVE_DAEMON_CALLER
            && !self
                .startup_coordinator
                .lock()
                .map_err(|_| TransportError::SessionFenced)?
                .admit_inspection()
        {
            // Control requests are decoded before this session path and keep
            // the bootstrap/probe route available. The daemon handshake and
            // the one-shot worker routes likewise remain available because
            // they establish the evidence needed to publish step 10.
            return Err(TransportError::SessionFenced);
        }
        let Ok(stored_policy) = self.front_door_policy.lock() else {
            audit_evidence.refuse(client, "kernel.handshake_policy_unavailable");
            return Err(TransportError::SessionFenced);
        };
        // I1.12 (#1968): the policy this session establishes with is a
        // per-session CLONE, and only a daemon client receives the five
        // compatibility envelope items in its `config_snapshot`. The stored
        // object is left exactly as `front_door_config_snapshot` built it
        // because the whole object is pinned by digest elsewhere; see
        // `front_door_handshake_policy`.
        let policy = match front_door_handshake_policy(&stored_policy, client) {
            Ok(policy) => policy,
            Err(cause) => {
                audit_evidence.refuse(client, cause);
                return Err(TransportError::SessionFenced);
            }
        };
        let result = Session::establish_with_server(connection_id, peer, client, &policy);
        if result.is_err() {
            audit_evidence.refuse(client, "handshake.session_establishment_rejected");
        }
        result
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
        let connection_id = connection_id.into();
        let peer_identity_well_formed = peer.validate().is_ok();
        let mut audit_evidence = DaemonSessionBindingAuditEvidence::default();
        let result =
            self.bind_session_inner(connection_id.clone(), peer, client, &mut audit_evidence);
        match &result {
            Ok(handshake) => {
                observe_front_door_session("kernel.front_door_handshake_accept", "success");
                // Issue #1837: durable audit evidence for session transition.
                // Issue #1807/W7: the accepted handshake carries the same
                // three separately-keyed facts and the same nonsecret owner
                // references the refused one carries. `peer_identity_well_formed`
                // and the collected owner evidence were already in hand here and
                // were being dropped, so the accepted leg — the one that actually
                // matters — stated no transport, operation or semantic-result
                // relation at all. Acceptance still implies no request
                // admission, so the draft keeps `operation_authorization` at
                // `not_assessed` and `semantic_result_acceptance` at
                // `not_reached`.
                self.audit_observe(AuditEventDraft::session_bound(
                    &handshake.session,
                    peer_identity_well_formed,
                    audit_evidence.owner_launch.as_ref(),
                    audit_evidence.owner_process_receipt.as_ref(),
                ));
            }
            Err(error) => {
                observe_front_door_session("kernel.front_door_handshake_reject", "fenced");
                super::kernel_diagnostics::observe_terminal_error(transport_terminal_code(error));
                if client.module_bridge_identity == ACTIVE_DAEMON_CALLER {
                    self.audit_observe(AuditEventDraft::session_rejected(
                        &connection_id,
                        peer_identity_well_formed,
                        transport_terminal_code(error),
                        audit_evidence.refusal_cause,
                        audit_evidence.owner_launch.as_ref(),
                        audit_evidence.owner_process_receipt.as_ref(),
                    ));
                }
            }
        }
        result
    }

    #[cfg(windows)]
    fn validate_eliotd_peer(
        &self,
        peer: &PeerIdentity,
        client: &eliot_protocol::ClientHello,
        audit_evidence: &mut DaemonSessionBindingAuditEvidence,
    ) -> Result<(), TransportError> {
        observe_front_door_session("kernel.front_door_eliotd_peer_validate", "attempt");
        let launch = match self.active_daemon_launch() {
            Ok(Some(launch)) => launch,
            Ok(None) => {
                audit_evidence.refuse(client, "daemon.active_launch_missing");
                return Err(TransportError::SessionFenced);
            }
            Err(_) => {
                audit_evidence.refuse(client, "daemon.active_launch_unavailable");
                return Err(TransportError::SessionFenced);
            }
        };
        audit_evidence.owner_launch = Some(launch.clone());
        self.validate_eliotd_client_claim(&launch, client, audit_evidence)?;
        let Some(peer_binding) = peer.process_binding() else {
            audit_evidence.refuse(client, "transport.peer_process_binding_unavailable");
            return Err(TransportError::PeerIdentityUnavailable);
        };
        let receipt = self.current_daemon_process_receipt(client, audit_evidence)?;
        Self::validate_daemon_receipt_binding(
            &launch,
            &receipt,
            peer_binding,
            client,
            audit_evidence,
        )?;
        Self::validate_daemon_job_membership(
            &launch,
            &receipt,
            peer_binding,
            client,
            audit_evidence,
        )
    }

    #[cfg(windows)]
    fn validate_eliotd_client_claim(
        &self,
        launch: &EliotdLaunchDescriptor,
        client: &eliot_protocol::ClientHello,
        audit_evidence: &mut DaemonSessionBindingAuditEvidence,
    ) -> Result<(), TransportError> {
        let policy = self.front_door_policy.lock().map_err(|_| {
            audit_evidence.refuse(client, "kernel.handshake_policy_unavailable");
            TransportError::SessionFenced
        })?;
        if let Err(error) = Self::validate_eliotd_client_binding(launch, &policy, client) {
            if let Some(cause) = Self::eliotd_client_binding_refusal_cause(launch, &policy, client)
            {
                audit_evidence.refuse(client, cause);
            }
            return Err(error);
        }
        drop(policy);
        Ok(())
    }

    #[cfg(windows)]
    fn current_daemon_process_receipt(
        &self,
        client: &eliot_protocol::ClientHello,
        audit_evidence: &mut DaemonSessionBindingAuditEvidence,
    ) -> Result<ProcessStartReceipt, TransportError> {
        let Ok(state) = self.daemon_runtime.lock() else {
            audit_evidence.refuse(client, "daemon.runtime_state_unavailable");
            return Err(TransportError::SessionFenced);
        };
        let receipt = match Self::published_daemon_receipt(&state) {
            Ok(receipt) => receipt,
            Err(error) => {
                audit_evidence.refuse(
                    client,
                    if matches!(&error, TransportError::PlanGap { .. }) {
                        "daemon.process_start_receipt_pending"
                    } else {
                        "daemon.process_start_receipt_missing"
                    },
                );
                return Err(error);
            }
        };
        if receipt.validate().is_err() {
            audit_evidence.refuse(client, "daemon.process_start_receipt_invalid");
            return Err(TransportError::SessionFenced);
        }
        audit_evidence.owner_process_receipt = Some(receipt.clone());
        Ok(receipt)
    }

    #[cfg(windows)]
    fn validate_daemon_receipt_binding(
        launch: &EliotdLaunchDescriptor,
        receipt: &ProcessStartReceipt,
        peer_binding: &eliot_ipc::ProcessBinding,
        client: &eliot_protocol::ClientHello,
        audit_evidence: &mut DaemonSessionBindingAuditEvidence,
    ) -> Result<(), TransportError> {
        let physical = receipt.identity().physical();
        if receipt.accepted_generation().get() != launch.generation.value() {
            audit_evidence.refuse(client, "process.receipt_generation_mismatch");
        } else if !receipt
            .binding()
            .state_fence()
            .authority_epoch()
            .is_same_authority(&launch.authority_epoch)
        {
            audit_evidence.refuse(client, "process.receipt_authority_epoch_mismatch");
        } else if receipt.identity().executable_sha256() != launch.executable_sha256 {
            audit_evidence.refuse(client, "process.receipt_executable_digest_mismatch");
        } else if peer_binding.process_id() != physical.process_id() {
            audit_evidence.refuse(client, "peer.process_id_mismatch");
        } else if peer_binding.start_time_100ns() != physical.start_time_100ns() {
            audit_evidence.refuse(client, "peer.process_start_time_mismatch");
        } else if !peer_binding
            .image_path()
            .eq_ignore_ascii_case(physical.image_path())
        {
            audit_evidence.refuse(client, "peer.image_path_mismatch");
        }
        if audit_evidence.refusal_cause.is_some() {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    #[cfg(windows)]
    fn validate_daemon_job_membership(
        launch: &EliotdLaunchDescriptor,
        receipt: &ProcessStartReceipt,
        peer_binding: &eliot_ipc::ProcessBinding,
        client: &eliot_protocol::ClientHello,
        audit_evidence: &mut DaemonSessionBindingAuditEvidence,
    ) -> Result<(), TransportError> {
        let physical = receipt.identity().physical();
        let observed = observe_named_pipe_peer_process_in_job(
            physical.executor_job_name(),
            physical.process_id(),
        )
        .map_err(|_| {
            audit_evidence.refuse(client, "peer.job_process_observation_unavailable");
            TransportError::SessionFenced
        })?;
        let observed_binding = observed.process_binding();
        if observed_binding.process_id() != peer_binding.process_id() {
            audit_evidence.refuse(client, "job_process.process_id_mismatch");
        } else if observed_binding.start_time_100ns() != peer_binding.start_time_100ns() {
            audit_evidence.refuse(client, "job_process.process_start_time_mismatch");
        } else if observed_binding.start_time_100ns() != physical.start_time_100ns() {
            audit_evidence.refuse(client, "job_process.receipt_start_time_mismatch");
        } else if !observed_binding
            .image_path()
            .eq_ignore_ascii_case(physical.image_path())
        {
            audit_evidence.refuse(client, "job_process.receipt_image_path_mismatch");
        } else if !observed_binding
            .image_path()
            .eq_ignore_ascii_case(launch.executable.as_str())
        {
            audit_evidence.refuse(client, "job_process.launch_image_path_mismatch");
        }
        if audit_evidence.refusal_cause.is_some() {
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
        if Self::eliotd_client_binding_refusal_cause(launch, policy, client).is_some() {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    #[cfg(windows)]
    fn eliotd_client_binding_refusal_cause(
        launch: &EliotdLaunchDescriptor,
        policy: &ServerHandshakePolicy,
        client: &eliot_protocol::ClientHello,
    ) -> Option<&'static str> {
        if client.artifact_hash.as_str() != policy.module_generation.artifact_id.as_str() {
            Some("client.artifact_hash_mismatch")
        } else if client.module_generation.artifact_id.as_str() != launch.executable_sha256.as_str()
        {
            Some("client.module_generation_artifact_id_mismatch")
        } else if client.module_generation.generation != launch.generation {
            Some("client.module_generation_generation_mismatch")
        } else if client.authority_epoch != launch.authority_epoch {
            Some("client.authority_epoch_mismatch")
        } else if client.launch_nonce.as_str() != launch.launch_nonce.as_str() {
            Some("client.launch_nonce_mismatch")
        } else {
            None
        }
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

    /// Binds the installer-pinned User Broker role to a scoped lifecycle
    /// session. The listener selected this role from the live OS peer, and
    /// this second gate joins the hello's exact module generation and artifact
    /// to that selected role and to the current Kernel authority fence.
    #[cfg(windows)]
    pub fn bind_user_broker_session(
        &self,
        connection_id: impl Into<String>,
        peer: PeerIdentity,
        selection: &eliot_platform_windows::NamedPipePeerSelection,
        client: &eliot_protocol::ClientHello,
    ) -> Result<HandshakeResult, TransportError> {
        let broker_capabilities = [
            USER_BROKER_REGISTER_OPERATION,
            USER_BROKER_HEARTBEAT_OPERATION,
            USER_BROKER_FENCE_OPERATION,
            USER_BROKER_VALIDATE_NATIVE_RESOURCE_SELECTION_CURRENT_OPERATION,
            // I11.8 (#1777): the fresh short-lived Operator session token the
            // WinUI client presents when it redeems its broker binding. It is
            // admitted here like the other four: the exact closed selector
            // must be the only entry this session may present, the binder
            // re-proves the live fence and Material authority, and the token
            // itself is minted by the Kernel owner, never by this session.
            USER_BROKER_BIND_OPERATOR_SESSION_TOKEN_OPERATION,
        ];

        observe_front_door_session("kernel.front_door_user_broker_bind", "attempt");
        let connection_id = connection_id.into();
        if selection.kind() != NamedPipePeerKind::UserBroker
            || selection.module_id() != NamedPipePeerKind::UserBroker.module_id()
            || client.module_bridge_identity != selection.module_id()
            || client.module_generation.module_id.as_str() != selection.module_id()
            || connection_id.trim().is_empty()
            || connection_id.chars().any(char::is_control)
        {
            return Err(TransportError::SessionFenced);
        }
        peer.validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let Some(expected_artifact) = self.user_broker_artifact_sha256.as_deref() else {
            return Err(TransportError::SessionFenced);
        };
        if client.artifact_hash.as_str() != expected_artifact
            || client.module_generation.artifact_id.as_str() != expected_artifact
            || client.module_contract.artifact_id.as_str() != expected_artifact
        {
            return Err(TransportError::SessionFenced);
        }
        let exactly_broker_capabilities = |capabilities: &[String]| {
            capabilities.len() == broker_capabilities.len()
                && broker_capabilities.iter().all(|expected| {
                    capabilities
                        .iter()
                        .filter(|capability| capability.as_str() == *expected)
                        .count()
                        == 1
                })
        };
        if !exactly_broker_capabilities(&client.capabilities)
            || !exactly_broker_capabilities(&client.module_contract.required_capabilities)
        {
            return Err(TransportError::SessionFenced);
        }

        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone();
        client.validate()?;
        if client.module_generation != policy.module_generation
            || !client
                .authority_epoch
                .is_same_authority(&policy.module_generation.state_fence.authority_epoch)
            || client.module_generation.state_fence != policy.module_generation.state_fence
        {
            return Err(TransportError::SessionFenced);
        }

        let mut session = Session::establish(connection_id, peer, client, policy.protocol_range)?;
        session.capabilities = broker_capabilities.into_iter().map(str::to_owned).collect();
        session
            .privacy_classes
            .retain(|class| policy.allowed_privacy_classes.contains(class));
        session.effects.clear();
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
        observe_front_door_session("kernel.front_door_user_broker_bind", "success");
        Ok(HandshakeResult {
            capabilities: session.capabilities.clone(),
            privacy_classes: session.privacy_classes.clone(),
            effects: Vec::new(),
            session,
            server_hello,
        })
    }

    /// Binds an authenticated Watchdog supervision service to a
    /// least-privilege session.
    ///
    /// The presenting pipe peer was already authenticated by the listener's
    /// peer set, which admitted the `Watchdog` role only against the process
    /// the platform adapter observed live from the canonical SCM service. This
    /// entry then proves the Watchdog `ClientHello` generation-bound against
    /// the live server policy (exact generation, exact artifact, same-authority
    /// epoch, compatible fence) and establishes the transport session.
    /// Capabilities are intersected down to the single admitted Watchdog wire
    /// operation and effects are never session-bound: the submission is an
    /// observation intake, and even that is re-resolved against the retained
    /// supervision lease inside
    /// [`KernelComposition::admit_watchdog_intent_batch`]. The issued
    /// `ServerHello` advertises exactly that one operation; an invalid peer or
    /// epoch fences before any protected input.
    ///
    /// The Watchdog gains no canonical, `HostStateJournal`, ORS-authoring,
    /// task, Architecture, completion, or budget authority here. The durable
    /// record this route stages is a non-canonical pending intent awaiting the
    /// Governor's own Problem/Incident transition.
    fn bind_watchdog_session(
        &self,
        connection_id: impl Into<String>,
        peer: PeerIdentity,
        client: &eliot_protocol::ClientHello,
    ) -> Result<HandshakeResult, eliot_ipc::TransportError> {
        observe_front_door_session("kernel.front_door_watchdog_bind", "attempt");
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
        Self::validate_watchdog_client_binding(&policy, client)?;
        let mut session = Session::establish(connection_id, peer, client, policy.protocol_range)?;
        session.capabilities = vec![
            WATCHDOG_INTENT_SUBMIT_OPERATION.to_owned(),
            WATCHDOG_EXPORT_SUBMIT_OPERATION.to_owned(),
        ];
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

    /// Proves a Watchdog `ClientHello` generation-bound against live server
    /// policy.
    ///
    /// Every Watchdog-asserted value is compared against the server-owned
    /// policy; nothing is copied into authority. The exact generation and
    /// artifact must match, the epoch must be the same authority, and the
    /// presented fence must be compatible with the live fence, so a stale or
    /// foreign generation can never bind. This is deliberately the same proof
    /// the Doctor, testd, and native-worker binds apply: pipe authentication
    /// plus this join, never a weaker substitute.
    fn validate_watchdog_client_binding(
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

/// I1.12 (#1968): the daemon-facing compatibility envelope producer, and the
/// closed shape every other caller must keep receiving.
///
/// Every expected value here is read from the OWNER crate
/// (`eliot_kernel_core`), never typed here, so a fixture cannot keep asserting
/// that a stale literal is published.
#[cfg(test)]
mod compatibility_envelope_projection_tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use eliot_contracts::ContractVersion;
    use eliot_runtime_contracts::ModuleContract;
    use serde::Deserialize;

    /// The five I1.12 items this producer adds, by the exact wire name the
    /// daemon receiver decodes them under.
    const ENVELOPE_KEYS: [&str; 5] = [
        "contract_set_digest",
        "canonical_format_range",
        "architecture_source_digest",
        "normative_pair_receipt",
        "state_migration_class",
    ];

    /// A closed mirror of the `config_snapshot` shape the two other consumers
    /// decode under `#[serde(deny_unknown_fields)]` (`eliot-cli`'s
    /// `KernelConfigSnapshot` and `eliot-mod-research`'s `ServerConfigSnapshot`).
    ///
    /// It is mirrored here rather than imported so the refusal an added key
    /// causes is observable in this file's own proof: decoding the daemon's
    /// extended object under this shape must fail. Both real decoders name
    /// exactly these keys, and `protected_snapshot_digest` is absent here
    /// because the composition under test is built with no daemon launch.
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ClosedGenerationSnapshot {
        service: String,
        protocol: String,
        generation: u64,
        authority_epoch: eliot_contracts::EpochId,
        artifact_digest: String,
    }

    fn temp_root(slug: &str) -> std::path::PathBuf {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis());
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-daemon-envelope-{slug}-{}-{ms}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        root
    }

    /// The STORED front-door policy, exactly as the composition built it.
    fn stored_front_door_policy(root: &std::path::Path) -> ServerHandshakePolicy {
        let kernel = KernelComposition::new(KernelConfig::new(root)).expect("kernel composition");
        let policy = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy")
            .clone();
        drop(kernel);
        policy
    }

    /// A `ClientHello` that matches the stored policy exactly, so
    /// `Session::establish_with_server` admits it for every field except the
    /// caller identity under test.
    fn client_hello_for(policy: &ServerHandshakePolicy) -> eliot_protocol::ClientHello {
        eliot_protocol::ClientHello {
            protocol_range: policy.protocol_range,
            module_bridge_identity: policy.module_id.clone(),
            artifact_hash: policy.module_generation.artifact_id.clone(),
            module_contract: ModuleContract {
                module_id: policy.module_generation.module_id.clone(),
                version: ContractVersion::new(1, 0, 0),
                artifact_id: policy.module_generation.artifact_id.clone(),
                protocols: vec![PROTOCOL_VERSION.to_owned()],
                capabilities: Vec::new(),
                required_capabilities: Vec::new(),
                optional_capabilities: Vec::new(),
                advisory_capabilities: Vec::new(),
                state_owner: SERVICE_NAME.to_owned(),
                failure_domain: SERVICE_NAME.to_owned(),
                owner: SERVICE_NAME.to_owned(),
                hot_replace: false,
                startup_after: Vec::new(),
                drain_before: Vec::new(),
                invalidation_triggers: Vec::new(),
                supervision_plan: "one_for_one".to_owned(),
                child_restart: "transient".to_owned(),
                restart_intensity: "3/10m".to_owned(),
                resource_profile: "background-medium".to_owned(),
                privacy_classes: vec!["PUBLIC".to_owned()],
                permissions: Vec::new(),
                health_contract: "health/test-v1".to_owned(),
                checkpoint_contract: "checkpoint/test-v1".to_owned(),
                compatibility_state: "rebuildable".to_owned(),
                independent_test_profile: "module/test".to_owned(),
                contract_fixture_set: "eliot.kernel.v1/test".to_owned(),
                affected_test_tags: vec!["test".to_owned()],
                architecture: Vec::new(),
                telemetry: "telemetry/test-v1".to_owned(),
                removal_boundary: SERVICE_NAME.to_owned(),
            },
            module_generation: policy.module_generation.clone(),
            launch_nonce: policy.launch_nonce.clone(),
            capabilities: policy.allowed_capabilities.clone(),
            privacy_classes: policy.allowed_privacy_classes.clone(),
            max_frame: policy.max_frame,
            authority_epoch: policy.module_generation.state_fence.authority_epoch.clone(),
        }
    }

    fn authenticated_peer() -> eliot_ipc::PeerIdentity {
        eliot_ipc::PeerIdentity::authenticated_for_test(
            eliot_ipc::ProcessBinding::from_observation(
                7,
                9,
                r"C:\eliot\kernel-test.exe".to_owned(),
            )
            .expect("process binding"),
            "S-1-5-19".to_owned(),
            "0x1".to_owned(),
        )
        .expect("authenticated peer")
    }

    /// This build's own contract-set digest, derived through the owner crate
    /// directly rather than through this binary's own adapter, so the assertion
    /// is not the producer compared with itself.
    fn owned_contract_set_digest() -> String {
        let identities = [
            eliot_kernel_core::contract_identity().expect("kernel-core identity"),
            eliot_kernel_service::contract_identity().expect("kernel-service identity"),
            eliot_protocol::protocol_contract_identity().expect("protocol identity"),
            eliot_runtime_contracts::contract_identity().expect("runtime-contracts identity"),
        ];
        eliot_kernel_core::contract_set_digest(&identities).expect("contract-set digest")
    }

    /// POSITIVE case: a daemon `ClientHello` yields a real `ServerHello` whose
    /// `config_snapshot` carries all five owner values, and the stored policy is
    /// byte-for-byte unchanged by producing them.
    ///
    /// Asserting the stored snapshot is unchanged is part of this case: the
    /// whole-object digest pin in `agent_bridge` compares against installation
    /// literals, so a producer that reached into the shared object would pass
    /// every assertion below and still refuse six binaries.
    #[test]
    fn a_daemon_client_hello_receives_the_five_owner_compatibility_items() {
        let root = temp_root("daemon");
        let stored = stored_front_door_policy(&root);
        let stored_snapshot = stored.config_snapshot.clone();
        let mut client = client_hello_for(&stored);
        client.module_bridge_identity = ACTIVE_DAEMON_CALLER.to_owned();
        assert_eq!(
            client.module_bridge_identity, stored.module_id,
            "the daemon identity is the front-door policy's own module identity"
        );

        let policy = front_door_handshake_policy(&stored, &client)
            .expect("this build must derive its own compatibility envelope");
        let handshake = Session::establish_with_server(
            "daemon-envelope",
            authenticated_peer(),
            &client,
            &policy,
        )
        .expect("daemon handshake");
        let published = handshake
            .server_hello
            .config_snapshot
            .as_object()
            .expect("the config_snapshot must be a JSON object");

        assert_eq!(
            published["contract_set_digest"],
            serde_json::json!(owned_contract_set_digest()),
            "the published contract-set digest must be the one this build derives"
        );
        assert_eq!(
            published["canonical_format_range"],
            serde_json::json!(
                eliot_kernel_core::handshake_canonical_format_range()
                    .expect("canonical format range")
            ),
            "the published canonical format range must be this build's own"
        );
        assert_eq!(
            published["architecture_source_digest"],
            serde_json::json!(eliot_kernel_core::CURRENT_ARCHITECTURE_SOURCE_DIGEST),
            "the published Architecture source digest must be this build's own constant"
        );
        let receipt: eliot_kernel_core::NormativePairReceipt =
            serde_json::from_value(published["normative_pair_receipt"].clone())
                .expect("the receipt must decode under the owner's own shape");
        assert_eq!(
            receipt.architecture_source_digest(),
            eliot_kernel_core::CURRENT_ARCHITECTURE_SOURCE_DIGEST,
            "the receipt must be minted over this build's own Architecture digest"
        );
        assert!(
            receipt.verifies(),
            "the published seal tag must be the owner's own recomputation"
        );
        assert_eq!(
            published["state_migration_class"],
            serde_json::json!(eliot_kernel_core::StateMigrationClass::NoMigration),
            "the published migration class must be the class this Kernel declares"
        );

        assert_eq!(
            stored.config_snapshot, stored_snapshot,
            "the stored policy object must be untouched by the per-session extension"
        );
        for key in ENVELOPE_KEYS {
            assert!(
                !stored_snapshot
                    .as_object()
                    .expect("the stored snapshot is an object")
                    .contains_key(key),
                "the stored policy must never carry {key}: the whole-object digest pin covers it"
            );
        }

        let _ = std::fs::remove_dir_all(root);
    }

    /// NEGATIVE case: a NON-daemon client hello keeps receiving the object with
    /// exactly its original keys.
    ///
    /// This is the case that protects the two closed decoders
    /// (`eliot-cli`, `eliot-mod-research`): the extended object is shown to be
    /// genuinely undecodable under their shape, so an extension that were not
    /// gated on the daemon identity would be observable here as a changed
    /// outcome rather than only as a different wire body.
    #[test]
    fn a_non_daemon_client_hello_receives_the_object_without_them() {
        let root = temp_root("non-daemon");
        let stored = stored_front_door_policy(&root);
        let mut client = client_hello_for(&stored);
        client.module_bridge_identity = eliot_kernel_service::STORE_MODULE_IDENTITY.to_owned();

        let policy = front_door_handshake_policy(&stored, &client)
            .expect("a non-daemon caller needs no envelope derivation");
        assert_eq!(
            policy.config_snapshot, stored.config_snapshot,
            "a non-daemon caller must receive the stored object byte-for-byte"
        );
        let object = policy
            .config_snapshot
            .as_object()
            .expect("the config_snapshot must be a JSON object");
        for key in ENVELOPE_KEYS {
            assert!(
                !object.contains_key(key),
                "a non-daemon caller must not receive {key}"
            );
        }
        let stored_artifact = stored.config_snapshot["artifact_digest"]
            .as_str()
            .expect("the stored snapshot carries the artifact digest")
            .to_owned();
        let closed: ClosedGenerationSnapshot =
            serde_json::from_value(policy.config_snapshot.clone())
                .expect("the closed generation-snapshot shape must still decode");
        assert_eq!(closed.service, SERVICE_NAME);
        assert_eq!(closed.protocol, PROTOCOL_VERSION);
        assert_eq!(
            closed.generation,
            stored.module_generation.generation.value(),
            "the object handed to a non-daemon caller is still this Kernel's own"
        );
        assert_eq!(
            closed.authority_epoch,
            stored.module_generation.state_fence.authority_epoch.clone()
        );
        assert_eq!(closed.artifact_digest, stored_artifact);

        let _ = std::fs::remove_dir_all(root);
    }

    /// The gate itself: the daemon's extended object really is refused by the
    /// closed shape, so gating on the daemon identity is load-bearing rather
    /// than cosmetic.
    #[test]
    fn the_daemon_extension_is_itself_refused_by_the_closed_shape() {
        let root = temp_root("closed-shape");
        let stored = stored_front_door_policy(&root);
        let mut client = client_hello_for(&stored);
        client.module_bridge_identity = ACTIVE_DAEMON_CALLER.to_owned();
        let policy = front_door_handshake_policy(&stored, &client)
            .expect("this build must derive its own compatibility envelope");

        assert!(
            serde_json::from_value::<ClosedGenerationSnapshot>(policy.config_snapshot).is_err(),
            "the extended object must be refused by the closed six-key decoders"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    /// REFUSAL CASE, and the measured ceiling it states: a policy object missing
    /// one of the six digest-pinned keys is PUBLISHED to the daemon, not repaired
    /// and not refused by this producer.
    ///
    /// `composition_bootstrap::front_door_config_snapshot` omits
    /// `protected_snapshot_digest` when the composition has no daemon launch, and
    /// nothing between it and `Session::establish_with_server` inspects the
    /// object's keys, so a `ServerHello` carrying only five of the six keys is
    /// what the daemon actually receives in that configuration. This test names
    /// that state instead of asserting a gate that does not exist: the refusal
    /// belongs to the receiver, whose decoder declares the key REQUIRED.
    ///
    /// What this producer does guarantee is the half it owns: it never INVENTS
    /// the missing digest-pinned key, so the object's absence stays visible to
    /// the receiver's own decode rather than being masked by a value the
    /// producer chose.
    #[test]
    fn a_policy_missing_a_digest_pinned_key_is_published_not_repaired() {
        let root = temp_root("missing-digest-pinned-key");
        let stored = stored_front_door_policy(&root);
        // The stored policy under test carries no `protected_snapshot_digest`:
        // this composition was built with no daemon launch, so the owner omits
        // it rather than defaulting one.
        let stored_object = stored
            .config_snapshot
            .as_object()
            .expect("the stored snapshot is an object");
        assert!(
            !stored_object.contains_key("protected_snapshot_digest"),
            "this fixture must actually be missing the digest-pinned key it claims to lose"
        );

        let mut client = client_hello_for(&stored);
        client.module_bridge_identity = ACTIVE_DAEMON_CALLER.to_owned();
        let policy = front_door_handshake_policy(&stored, &client)
            .expect("this build must derive its own compatibility envelope");

        let published = policy
            .config_snapshot
            .as_object()
            .expect("the published snapshot is an object");
        assert!(
            !published.contains_key("protected_snapshot_digest"),
            "the producer must never invent a digest-pinned key it was not given"
        );
        for key in ENVELOPE_KEYS {
            assert!(
                published.contains_key(key),
                "the five envelope items are still published alongside the incomplete object: {key}"
            );
        }
        assert!(
            serde_json::from_value::<ClosedGenerationSnapshot>(policy.config_snapshot).is_err(),
            "the incomplete object must remain undecodable under the receiver's closed shape, \
             so its absence is the receiver's refusal rather than a silent repair"
        );

        let _ = std::fs::remove_dir_all(root);
    }
}
