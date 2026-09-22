//! Kernel control-plane transition and authenticated request handling.
//!
//! Architecture traceability:
//! - `ELIOT_ARCHITECTURE.md :: A13.2. Kernel и failure domains` keeps Kernel
//!   as the lifecycle and failure boundary for this control path.
//! - `ELIOT_ARCHITECTURE.md :: A13.5. Bounded resources и Control Reserve`
//!   binds control work to the existing protected-control reserve; this module
//!   exposes its capacity without creating a second budget.
//! - `ELIOT_IMPLEMENTATION.md :: P.3. Kernel control boundary` keeps
//!   front-door request admission and lifecycle transitions in Kernel while
//!   service semantics stay behind the existing `KernelService` gateway.
//! - `ELIOT_IMPLEMENTATION.md :: I1.5. Demand-start, observable use,
//!   supervision and idle shutdown` and `I14.13. Idle drain and cancellation`
//!   constrain shutdown to the existing runtime signal and drain owners.
//! - `ELIOT_IMPLEMENTATION.md :: I14.23. Safe shutdown` leaves the complete
//!   cooperative shutdown sequence in `KernelComposition::shutdown`.
//!
//! The implementation remains an ordinary module so the composition root keeps
//! its public API while the control-plane lifecycle gateway has a bounded home.

use super::*;

const RUNTIME_LEASE_TTL_MS: u64 = 5 * 60 * 1_000;
const RUNTIME_LEASE_RENEW_BEFORE_MS: u64 = 60 * 1_000;

#[derive(Clone, Debug)]
enum RuntimeLeaseOwnerRef {
    HostRequest {
        operation_id: String,
        request_digest: String,
    },
    DoctorAttempt(String),
    DoctorEffect(String),
    NativeWorkerClaim(String),
}

#[derive(Clone, Debug)]
struct RuntimeLeaseOwnerObservation {
    admission: RuntimeLeaseAdmission,
    renewal_evidence_refs: Vec<PlatformHandle>,
    renewal_evidence: Vec<String>,
    admitted_wait: bool,
    active: bool,
    renewable: bool,
}

fn runtime_lease_owner_ref(value: &str) -> Result<RuntimeLeaseOwnerRef, TransportError> {
    if let Some(value) = value.strip_prefix("owner:host-request:") {
        let (operation_id, request_digest) = value
            .rsplit_once("::")
            .ok_or(TransportError::SessionFenced)?;
        if operation_id.trim().is_empty()
            || request_digest.len() != 64
            || !request_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(TransportError::SessionFenced);
        }
        return Ok(RuntimeLeaseOwnerRef::HostRequest {
            operation_id: operation_id.to_owned(),
            request_digest: request_digest.to_owned(),
        });
    }
    for (prefix, constructor) in [
        (
            "owner:doctor-attempt:",
            RuntimeLeaseOwnerRef::DoctorAttempt as fn(String) -> RuntimeLeaseOwnerRef,
        ),
        (
            "owner:doctor-effect:",
            RuntimeLeaseOwnerRef::DoctorEffect as fn(String) -> RuntimeLeaseOwnerRef,
        ),
        (
            "owner:native-claim:",
            RuntimeLeaseOwnerRef::NativeWorkerClaim as fn(String) -> RuntimeLeaseOwnerRef,
        ),
    ] {
        if let Some(identity) = value.strip_prefix(prefix) {
            if identity.trim().is_empty() {
                return Err(TransportError::SessionFenced);
            }
            return Ok(constructor(identity.to_owned()));
        }
    }
    Err(TransportError::SessionFenced)
}

fn runtime_lease_owner_ref_string(owner: &RuntimeLeaseOwnerRef) -> String {
    match owner {
        RuntimeLeaseOwnerRef::HostRequest {
            operation_id,
            request_digest,
        } => format!("owner:host-request:{operation_id}::{request_digest}"),
        RuntimeLeaseOwnerRef::DoctorAttempt(identity) => {
            format!("owner:doctor-attempt:{identity}")
        }
        RuntimeLeaseOwnerRef::DoctorEffect(identity) => {
            format!("owner:doctor-effect:{identity}")
        }
        RuntimeLeaseOwnerRef::NativeWorkerClaim(identity) => {
            format!("owner:native-claim:{identity}")
        }
    }
}

fn runtime_lease_owner_kind(owner: &RuntimeLeaseOwnerRef) -> eliot_kernel_service::RuntimeLeaseOwnerKind {
    match owner {
        RuntimeLeaseOwnerRef::HostRequest { .. } => {
            eliot_kernel_service::RuntimeLeaseOwnerKind::Session
        }
        RuntimeLeaseOwnerRef::DoctorAttempt(_) => {
            eliot_kernel_service::RuntimeLeaseOwnerKind::Attempt
        }
        RuntimeLeaseOwnerRef::DoctorEffect(_) => {
            eliot_kernel_service::RuntimeLeaseOwnerKind::Effect
        }
        RuntimeLeaseOwnerRef::NativeWorkerClaim(_) => {
            eliot_kernel_service::RuntimeLeaseOwnerKind::Job
        }
    }
}

fn runtime_lease_handle(value: impl Into<String>) -> Result<PlatformHandle, TransportError> {
    PlatformHandle::new(value.into()).map_err(|_| TransportError::SessionFenced)
}

fn runtime_lease_handles(
    values: impl IntoIterator<Item = String>,
) -> Result<Vec<PlatformHandle>, TransportError> {
    values.into_iter().map(runtime_lease_handle).collect()
}

fn runtime_lease_digest(value: &str) -> Result<(), TransportError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

fn runtime_lease_state_fence_digest(fence: &StateFence) -> Result<String, TransportError> {
    let bytes = eliot_contracts::canonical_json_bytes(fence)
        .map_err(|_| TransportError::SessionFenced)?;
    Ok(eliot_contracts::sha256_hex(&bytes))
}

fn runtime_lease_now_nanos() -> u64 {
    unix_ms().saturating_mul(1_000_000)
}

fn runtime_lease_host_request_kind(kind: eliot_ors::HostRequestKind) -> &'static str {
    match kind {
        eliot_ors::HostRequestKind::Activation => "activation",
        eliot_ors::HostRequestKind::Invocation => "invocation",
        eliot_ors::HostRequestKind::Cancellation => "cancellation",
        eliot_ors::HostRequestKind::Status => "status",
        eliot_ors::HostRequestKind::Reconciliation => "reconciliation",
    }
}

fn runtime_lease_host_request_active(state: eliot_ors::HostRequestState) -> bool {
    matches!(
        state,
        eliot_ors::HostRequestState::Admitted
            | eliot_ors::HostRequestState::Routed
            | eliot_ors::HostRequestState::Submitted
            | eliot_ors::HostRequestState::PossiblyEffected
            | eliot_ors::HostRequestState::Unknown
            | eliot_ors::HostRequestState::Reconciling
    )
}

fn runtime_lease_attempt_active(state: eliot_ors::DoctorAttemptState) -> bool {
    matches!(
        state,
        eliot_ors::DoctorAttemptState::Admitted
            | eliot_ors::DoctorAttemptState::EffectIntended
            | eliot_ors::DoctorAttemptState::Unknown
            | eliot_ors::DoctorAttemptState::Reconciling
    )
}

fn runtime_lease_effect_active(state: eliot_ors::DoctorEffectState) -> bool {
    matches!(
        state,
        eliot_ors::DoctorEffectState::Intended
            | eliot_ors::DoctorEffectState::Unknown
            | eliot_ors::DoctorEffectState::Reconciling
    )
}

fn runtime_lease_claim_active(state: eliot_ors::NativeWorkerClaimState) -> bool {
    !matches!(
        state,
        eliot_ors::NativeWorkerClaimState::Requested
            | eliot_ors::NativeWorkerClaimState::Terminal
    )
}

/// F-LOG-KERNEL-4 (#903): control-plane boundary observations.
///
/// Observation only, via #895's facade: fixed `kernel.control.*` event names
/// plus a bounded stable outcome. Never carries request payloads, digests,
/// peer identities, pipe names, or owner error strings (I15.4, I07.20).
fn observe_control(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "control plane observation"
    );
}

/// Maps one control-transition failure to its stable diagnostic code.
///
/// Only the variant is emitted; any `String` payload or embedded state is
/// never logged.
fn control_transition_terminal_code(error: &KernelServiceError) -> &'static str {
    match error {
        KernelServiceError::InvalidField { .. } => "CONTROL_INVALID_FIELD",
        KernelServiceError::IllegalTransition { .. } => "CONTROL_ILLEGAL_TRANSITION",
        KernelServiceError::HandshakeMismatch { .. } => "CONTROL_HANDSHAKE_MISMATCH",
        KernelServiceError::MissingContainmentEvidence => "CONTROL_MISSING_CONTAINMENT",
        KernelServiceError::ReadinessNotProven => "CONTROL_READINESS_NOT_PROVEN",
        KernelServiceError::AdmissionClosed(_) => "CONTROL_ADMISSION_CLOSED",
        KernelServiceError::GenerationFenced => "CONTROL_GENERATION_FENCED",
        KernelServiceError::RestartBudgetExhausted => "CONTROL_RESTART_BUDGET_EXHAUSTED",
        KernelServiceError::ControlReserveExhausted => "CONTROL_RESERVE_EXHAUSTED",
        KernelServiceError::Platform(_) => "CONTROL_PLATFORM",
        KernelServiceError::Core(_) => "CONTROL_CORE",
    }
}

/// Maps one authenticated control-request failure to its stable diagnostic
/// code.
///
/// Only the variant is emitted; any `String` payload is never logged. The
/// `control_` prefix keeps request-operation terminals distinct from other
/// `TransportError` owners (`frame_*`, `daemon_*`).
fn control_request_terminal_code(error: &TransportError) -> &'static str {
    match error {
        TransportError::InvalidLimits => "control_invalid_limits",
        TransportError::UnauthenticatedPeer => "control_unauthenticated_peer",
        TransportError::PeerIdentityUnavailable => "control_peer_unavailable",
        TransportError::Protocol(_) => "control_protocol",
        TransportError::SessionFenced => "control_fenced",
        TransportError::Backpressure => "control_backpressure",
        TransportError::Timeout => "control_timeout",
        TransportError::Cancelled => "control_cancelled",
        TransportError::InvalidPipeName => "control_invalid_pipe",
        TransportError::UnknownOutcome => "control_unknown_outcome",
        TransportError::Io(_) => "control_io",
        TransportError::PlanGap { .. } => "control_plan_gap",
        TransportError::UnknownRequest => "control_unknown_request",
        TransportError::IdentityConflict => "control_identity_conflict",
        TransportError::RegistryFull => "control_registry_full",
    }
}

/// Observes one protected-control capacity read with its bounded count.
///
/// The count is a small nonsecret integer; it is still routed through the
/// bounded field helper so the observation keeps the `MAX_FIELD` shape.
fn observe_control_capacity(capacity: usize) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field("kernel.control.capacity_observed");
    let capacity_bound = bound_field(&capacity.to_string());
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        capacity = capacity_bound.text(),
        "control capacity observation"
    );
}

/// Verifies the independent-supervision (watchdog) branch backing one Windows
/// `ProbeReady` admission: the candidate's supervision incarnation must carry
/// a usable watchdog epoch, and the renewed ORS head behind this probe's
/// supervision lease must carry that exact same epoch.
///
/// Fail-closed `SessionFenced` otherwise: on Windows the Kernel never authors
/// a ready receipt — and never returns a supervision lease — as
/// independently supervised when the watchdog branch is missing or foreign.
/// Per I1.5, Material work requiring independent supervision is then paused
/// (Host degrades the readiness contour into a human-visible coverage gap)
/// instead of being admitted as supervised. Non-Windows builds have no
/// equivalent gate yet (Linux supervision port, I1.7) and therefore emit no
/// supervised readiness at all: `ProbeReady` fails closed below before any
/// receipt or supervision lease is produced.
#[cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "the verified-watchdog ProbeReady gate has no non-Windows caller until the Linux supervision port lands (I1.7)"
    )
)]
fn verify_probe_watchdog_branch(
    incarnation_watchdog_sequence: u64,
    binding_watchdog_sequence: u64,
) -> Result<(), TransportError> {
    if incarnation_watchdog_sequence == 0
        || binding_watchdog_sequence == 0
        || incarnation_watchdog_sequence != binding_watchdog_sequence
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

impl KernelComposition {
    /// Applies one lifecycle command through the sole Kernel transition gateway.
    ///
    /// Diagnostic wrapper (F-LOG-KERNEL-4, #903): exactly one terminal is
    /// emitted per failed transition; the admitted state versus the failure
    /// record stay distinct, and no command or error material is logged.
    pub fn apply_control(
        &self,
        command: KernelControlCommand,
    ) -> Result<KernelServiceState, KernelServiceError> {
        observe_control("kernel.control.transition_requested", "attempt");
        match self.apply_control_inner(command) {
            Ok(state) => {
                observe_control("kernel.control.transition_committed", "success");
                Ok(state)
            }
            Err(error) => {
                observe_control("kernel.control.transition_failed", "rejected");
                super::kernel_diagnostics::observe_terminal_error(
                    control_transition_terminal_code(&error),
                );
                Err(error)
            }
        }
    }

    /// Transition sequence; every fence check precedes the single service
    /// application. See [`KernelComposition::apply_control`].
    fn apply_control_inner(
        &self,
        command: KernelControlCommand,
    ) -> Result<KernelServiceState, KernelServiceError> {
        if let Some(reason) = self
            .generation_poison
            .lock()
            .map_err(|_| {
                KernelServiceError::Platform("generation poison lock poisoned".to_owned())
            })?
            .clone()
        {
            return Err(KernelServiceError::Platform(format!(
                "generation gateway fenced: {reason}"
            )));
        }
        self.service
            .lock()
            .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?
            .apply(command)
    }

    /// Applies one authenticated Host control request after binding the
    /// transport's handle-proven peer and the approved generation contour.
    ///
    /// Diagnostic wrapper (F-LOG-KERNEL-4, #903): exactly one terminal is
    /// emitted per failed request with the request operation's own stable
    /// code; failures already terminaled by the transition gateway below
    /// arrive here transformed into the request error, never re-terminaled
    /// under their original value.
    pub async fn apply_control_request(
        &self,
        request: KernelControlRequest,
        peer: &PeerIdentity,
        expected_sequence: u64,
    ) -> Result<KernelControlResponse, TransportError> {
        observe_control("kernel.control.request_received", "attempt");
        match Box::pin(self.apply_control_request_inner(request, peer, expected_sequence)).await {
            Ok(response) => {
                observe_control("kernel.control.request_admitted", "success");
                Ok(response)
            }
            Err(error) => {
                observe_control("kernel.control.request_denied", "rejected");
                super::kernel_diagnostics::observe_terminal_error(control_request_terminal_code(
                    &error,
                ));
                Err(error)
            }
        }
    }

    /// Authenticated validation and command-order sequence; every admission
    /// check precedes the single transition gateway call. See
    /// [`KernelComposition::apply_control_request`].
    #[allow(
        clippy::too_many_lines,
        reason = "the authenticated control handler preserves one visible validation and command-order boundary"
    )]
    async fn apply_control_request_inner(
        &self,
        request: KernelControlRequest,
        peer: &PeerIdentity,
        expected_sequence: u64,
    ) -> Result<KernelControlResponse, TransportError> {
        request
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        peer.validate()?;
        let observed_peer = peer
            .process_binding()
            .ok_or(TransportError::PeerIdentityUnavailable)?;
        if request.sequence != expected_sequence
            || request.peer_process_id != observed_peer.process_id()
            || request.candidate.pipe_identity.as_str() != self.ipc.name()
            || observed_peer.process_id() != request.candidate.host_process.process_id
            || observed_peer.start_time_100ns() != request.candidate.host_process.start_time_100ns
            || observed_peer.image_path() != request.candidate.host_process.image_path
        {
            return Err(TransportError::SessionFenced);
        }
        #[cfg(windows)]
        self.validate_candidate_process_binding(&request.candidate)
            .map_err(|_| TransportError::SessionFenced)?;
        let bootstrap = match &request.command {
            KernelControlCommand::BootstrapStore(handoff) => Some(handoff.clone()),
            _ => None,
        };
        #[cfg(windows)]
        let _store_rebind_guard = if matches!(
            &request.command,
            KernelControlCommand::BootstrapStore(_)
                | KernelControlCommand::RebindStore(_)
                | KernelControlCommand::ReconcileRebindStore(_)
                | KernelControlCommand::Reconcile
                | KernelControlCommand::ProbeReady
        ) {
            Some(self.store_rebind_gate.lock().await)
        } else {
            None
        };
        #[cfg(windows)]
        self.validate_store_rebind_admission(&request)?;
        {
            let mut policy = self
                .front_door_policy
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let reconcile = matches!(&request.command, KernelControlCommand::Reconcile);
            let policy_epoch = policy.module_generation.state_fence.authority_epoch.clone();
            let epoch_mismatch = {
                let candidate = &request.candidate.kernel_epoch;
                !(candidate.is_same_authority(&policy_epoch)
                    || (reconcile
                        && candidate.lineage_id == policy_epoch.lineage_id
                        && candidate.sequence.get() > policy_epoch.sequence.get()))
            };
            if request.generation != policy.module_generation.generation
                || epoch_mismatch
                || self
                    .kernel_artifact_sha256
                    .as_deref()
                    .is_some_and(|digest| request.candidate.artifact_hash.as_str() != digest)
                || self
                    .approved_config_hash
                    .as_deref()
                    .is_some_and(|hash| hash != request.candidate.config_hash.as_str())
            {
                return Err(TransportError::SessionFenced);
            }
            if !request
                .candidate
                .kernel_epoch
                .is_same_authority(&policy_epoch)
            {
                self.service
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?
                    .synchronize_authority_epoch(request.candidate.kernel_epoch.clone())
                    .map_err(|_| TransportError::SessionFenced)?;
                policy.module_generation.state_fence =
                    StateFence::new(request.candidate.kernel_epoch.clone(), request.generation);
            }
        }
        if let KernelControlCommand::ReportHostStartupEvidence(evidence) = &request.command {
            self.consume_host_startup_evidence(evidence)?;
        }
        if let Some(handoff) = bootstrap {
            self.install_store_bootstrap(handoff.clone())
                .map_err(|_| TransportError::SessionFenced)?;
            if let Err(error) = self
                .connect_canonical_store(Duration::from_millis(handoff.requirement.timeout_ms()))
                .await
            {
                let _ = error;
                return Err(TransportError::SessionFenced);
            }
        }
        // I14.23 wake/attach race: a new activation arriving before the
        // `DrainCommit` linearization point cancels the drain and proceeds;
        // after linearization it cannot reuse the drained generation (the
        // service independently fences `Activate` from `Draining`) and must
        // re-establish a fresh generation through the reconcile path.
        if matches!(&request.command, KernelControlCommand::Activate(_)) {
            // Post-linearization activation cannot reuse the drained
            // generation; the caller re-establishes a fresh generation
            // through the reconcile path.
            if coordinator_for(&self.work_root)
                .on_activate_request()
                .fences_old_authority()
            {
                return Err(TransportError::SessionFenced);
            }
        }
        let store_rebind_receipt: Option<eliot_kernel_service::StoreRebindReceipt> = match &request
            .command
        {
            KernelControlCommand::RebindStore(handoff) => {
                let receipt = self
                    .rebind_store(handoff.clone(), request.payload_digest.clone())
                    .await
                    .map_err(|_| TransportError::SessionFenced)?;
                Some(receipt)
            }
            KernelControlCommand::ReconcileRebindStore(query) => {
                let op_id = eliot_ors::OperationIdentity::new(query.operation_id.as_str())
                    .map_err(|_| TransportError::SessionFenced)?;
                let record = self
                    .generation_gateway
                    .ors
                    .load_store_rebind(&op_id, &query.request_digest)
                    .map_err(|_| TransportError::SessionFenced)?;
                match record {
                    Some(record)
                        if record.state == eliot_ors::StoreRebindReplayState::Committed
                            && record.operation_id.as_str() == query.operation_id.as_str()
                            && record.request_digest == query.request_digest
                            && record.receipt.as_deref() == Some(query.request_digest.as_str()) =>
                    {
                        Self::validate_store_rebind_ors_record_admission(&request, query, &record)?;
                        if !is_store_rebind_latest_committed(&self.generation_gateway.ors, &record)
                            .map_err(|_| TransportError::SessionFenced)?
                        {
                            return Err(TransportError::SessionFenced);
                        }
                        let receipt = store_rebind_receipt_from_ors_record(
                            &record,
                            &request.candidate.kernel_epoch,
                        )
                        .map_err(|_| TransportError::SessionFenced)?;
                        self.verify_store_rebind_publication_complete(&receipt)?;
                        // A reconciled commit resolves the matching drain-gate
                        // receipt when a shutdown is waiting on it.
                        coordinator_for(&self.work_root).resolve_pending_receipt(&format!(
                            "store-rebind:{}",
                            query.operation_id.as_str()
                        ));
                        Some(receipt)
                    }
                    Some(record)
                        if record.state == eliot_ors::StoreRebindReplayState::Pending
                            && record.operation_id.as_str() == query.operation_id.as_str()
                            && record.request_digest == query.request_digest =>
                    {
                        // A Pending ORS row has no terminal outcome.  Resolve
                        // it under the same gate before allowing Host to write
                        // an Aborted disposition; a failed compare-delete or
                        // non-terminal readback remains fenced/unknown.
                        let removed = self
                            .generation_gateway
                            .ors
                            .abort_store_rebind(&op_id, &query.request_digest)
                            .map_err(|_| TransportError::SessionFenced)?;
                        let after = self
                            .generation_gateway
                            .ors
                            .load_store_rebind(&op_id, &query.request_digest)
                            .map_err(|_| TransportError::SessionFenced)?;
                        match (removed, after) {
                            (_, None) => {
                                self.rollback_store_rebind_if_exact_query(query)?;
                                // The abort removed the staged row, resolving
                                // the matching drain-gate receipt if any.
                                coordinator_for(&self.work_root).resolve_pending_receipt(&format!(
                                    "store-rebind:{}",
                                    query.operation_id.as_str()
                                ));
                                None
                            }
                            (_, Some(after))
                                if after.state == eliot_ors::StoreRebindReplayState::Committed
                                    && after.operation_id.as_str()
                                        == query.operation_id.as_str()
                                    && after.request_digest == query.request_digest
                                    && after.receipt.as_deref()
                                        == Some(query.request_digest.as_str()) =>
                            {
                                Self::validate_store_rebind_ors_record_admission(
                                    &request, query, &after,
                                )?;
                                if !is_store_rebind_latest_committed(
                                    &self.generation_gateway.ors,
                                    &after,
                                )
                                .map_err(|_| TransportError::SessionFenced)?
                                {
                                    return Err(TransportError::SessionFenced);
                                }
                                let receipt = store_rebind_receipt_from_ors_record(
                                    &after,
                                    &request.candidate.kernel_epoch,
                                )
                                .map_err(|_| TransportError::SessionFenced)?;
                                self.verify_store_rebind_publication_complete(&receipt)?;
                                // A reconciled commit resolves the matching
                                // drain-gate receipt when a shutdown waits.
                                coordinator_for(&self.work_root).resolve_pending_receipt(&format!(
                                    "store-rebind:{}",
                                    query.operation_id.as_str()
                                ));
                                Some(receipt)
                            }
                            _ => return Err(TransportError::SessionFenced),
                        }
                    }
                    Some(_) => return Err(TransportError::SessionFenced),
                    None => {
                        // A service receipt without an exact durable ORS
                        // commit is intentionally not query-visible. In
                        // particular, this closes the window after service
                        // mutation and before ORS begin/commit; the caller
                        // must retain Pending/Unknown and retry the exact
                        // operation instead of terminalizing from volatile
                        // memory.
                        self.rollback_store_rebind_if_exact_query(query)?;
                        None
                    }
                }
            }
            _ => None,
        };
        let is_probe = matches!(&request.command, KernelControlCommand::ProbeReady);
        #[cfg(windows)]
        let supervision_publication = if is_probe {
            Some(
                self.renew_daemon_supervision_for_probe(&request)
                    .map_err(|_| TransportError::SessionFenced)?,
            )
        } else {
            None
        };
        #[cfg(windows)]
        let supervision_lease = supervision_publication
            .as_ref()
            .map(|(snapshot, _)| snapshot.clone());
        #[cfg(not(windows))]
        let supervision_lease = None;
        #[cfg(windows)]
        if let Some((renewed_head, _)) = supervision_publication.as_ref() {
            // I1.5 (#1750, Windows-only gate): the ProbeReady admission never
            // proceeds as independently supervised without the verified
            // watchdog branch. This runs before any ready receipt is authored,
            // and the readbacks below confirm the gated head is still current,
            // so a refusal surfaces as degraded readiness instead of
            // supervised health. Non-Windows builds never reach a supervised
            // admission: ProbeReady fails closed below (I1.7).
            verify_probe_watchdog_branch(
                request
                    .candidate
                    .supervision_incarnation
                    .watchdog_epoch
                    .sequence,
                renewed_head.record.binding.watchdog_epoch.value(),
            )?;
        }
        let receipt = if is_probe {
            #[cfg(windows)]
            {
                Some(
                    self.self_authored_ready_receipt(&request, peer)
                        .await
                        .map_err(|_| TransportError::SessionFenced)?,
                )
            }
            #[cfg(not(windows))]
            {
                // Containment (I1.7): without the verified watchdog-branch gate
                // there is no equivalent supervision proof on this platform, so
                // no ready receipt — and no supervised-readiness claim of any
                // kind — may be emitted here.
                return Err(TransportError::SessionFenced);
            }
        } else {
            None
        };
        #[cfg(windows)]
        if let Some((expected, expected_live_receipt)) = supervision_publication.as_ref() {
            let after = self
                .supervision_lease_authority
                .as_ref()
                .ok_or(TransportError::SessionFenced)?
                .current_snapshot(
                    &request
                        .candidate
                        .supervision_incarnation
                        .supervision_lease_id,
                )
                .map_err(|_| TransportError::SessionFenced)?;
            if after.as_ref() != Some(expected) {
                return Err(TransportError::SessionFenced);
            }
            self.verify_published_eliotd_live_receipt(expected_live_receipt)
                .map_err(|_| TransportError::SessionFenced)?;
            let after_receipt_readback = self
                .supervision_lease_authority
                .as_ref()
                .ok_or(TransportError::SessionFenced)?
                .current_snapshot(
                    &request
                        .candidate
                        .supervision_incarnation
                        .supervision_lease_id,
                )
                .map_err(|_| TransportError::SessionFenced)?;
            if after_receipt_readback.as_ref() != Some(expected) {
                return Err(TransportError::SessionFenced);
            }
            self.record_startup_evidence(11)
                .map_err(|_| TransportError::SessionFenced)?;
        }
        #[cfg(windows)]
        let prepared_bridge_profile = if matches!(
            &request.command,
            KernelControlCommand::Activate(_) | KernelControlCommand::ProbeReady
        ) {
            Some(Self::prepare_agent_bridge_admission(
                request.candidate.agent_bridge_admission.as_ref(),
            )?)
        } else {
            None
        };
        #[cfg(windows)]
        if matches!(&request.command, KernelControlCommand::Activate(_)) {
            // A new candidate immediately revokes the prior bridge lineage;
            // it is republished only after this candidate reaches Ready.
            self.promote_agent_bridge_profile(None)?;
        }
        let activation_receipt: Option<KernelActivationReceipt> = match &request.command {
            KernelControlCommand::Activate(permit) => Some(
                self.service
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?
                    .activate_permit(permit, request.generation, request.payload_digest.clone())
                    .map_err(|_| TransportError::SessionFenced)?,
            ),
            KernelControlCommand::ReconcileActivation(query) => self
                .service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?
                .reconcile_activation(query)
                .map_err(|_| TransportError::SessionFenced)?,
            _ => None,
        };
        #[cfg(windows)]
        if matches!(&request.command, KernelControlCommand::Activate(_))
            && self
                .active_daemon_launch()
                .map_err(|_| TransportError::SessionFenced)?
                .is_some()
        {
            let launched = self
                .launch_eliotd()
                .await
                .map_err(|_| TransportError::SessionFenced)?;
            self.await_daemon_ready(&launched, self.ipc_limits().operation_timeout)
                .await
                .map_err(|_| TransportError::SessionFenced)?;
        }
        if let Some(receipt) = &receipt {
            self.service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?
                .publish_ready(receipt.clone())
                .map_err(|_| TransportError::SessionFenced)?;
            self.record_startup_evidence(10)
                .map_err(|_| TransportError::SessionFenced)?;
        } else {
            match &request.command {
                KernelControlCommand::Reconcile => self
                    .service
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?
                    .reconcile(request.candidate.clone())
                    .map_err(|_| TransportError::SessionFenced)?,
                KernelControlCommand::BootstrapStore(_)
                | KernelControlCommand::Activate(_)
                | KernelControlCommand::ReconcileActivation(_)
                | KernelControlCommand::RebindStore(_)
                | KernelControlCommand::ReconcileRebindStore(_)
                | KernelControlCommand::ReportHostStartupEvidence(_)
                | KernelControlCommand::AcquireRuntimeLease(_)
                | KernelControlCommand::RenewRuntimeLease(_)
                | KernelControlCommand::RevokeRuntimeLease(_)
                | KernelControlCommand::ExpireRuntimeLease(_)
                | KernelControlCommand::CloseRuntimeLease(_)
                | KernelControlCommand::ReconcileRuntimeLease(_) => {}
                command => {
                    self.apply_control(command.clone())
                        .map_err(|_| TransportError::SessionFenced)?;
                }
            }
        }
        #[cfg(windows)]
        if matches!(&request.command, KernelControlCommand::ProbeReady)
            && let Some(next) = prepared_bridge_profile
        {
            self.promote_agent_bridge_profile(next)?;
        }
        let runtime_lease = match &request.command {
            KernelControlCommand::AcquireRuntimeLease(admission) => {
                Some(self.acquire_runtime_lease(&request, admission)?)
            }
            KernelControlCommand::RenewRuntimeLease(renewal) => {
                Some(self.renew_runtime_lease(&request, renewal)?)
            }
            KernelControlCommand::RevokeRuntimeLease(terminal) => Some(
                self.transition_runtime_lease(&request, terminal, LeaseState::Revoked)?,
            ),
            KernelControlCommand::ExpireRuntimeLease(terminal) => Some(
                self.transition_runtime_lease(&request, terminal, LeaseState::Expired)?,
            ),
            KernelControlCommand::CloseRuntimeLease(terminal) => Some(
                self.transition_runtime_lease(&request, terminal, LeaseState::Closed)?,
            ),
            KernelControlCommand::ReconcileRuntimeLease(reconcile) => {
                self.reconcile_runtime_lease(&request, reconcile)?
            }
            KernelControlCommand::ProbeReady => None,
            _ => None,
        };
        let state = self
            .service_state()
            .map_err(|_| TransportError::SessionFenced)?;
        let runtime_health = if is_probe {
            Some(self.runtime_health_evidence_for_control(
                request.generation,
                &request.candidate.kernel_epoch,
            )?)
        } else {
            None
        };
        KernelControlResponse {
            wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
            wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
            message_id: request.message_id,
            request_digest: request.payload_digest,
            state,
            receipt,
            runtime_health,
            activation_receipt,
            store_rebind_receipt,
            supervision_lease,
            runtime_lease,
            error: None,
            payload_digest: String::new(),
        }
        .with_computed_digest()
        .map_err(|_| TransportError::SessionFenced)
    }

    fn validate_runtime_lease_owner(
        &self,
        request: &KernelControlRequest,
        lease: &RuntimeLease,
    ) -> Result<(), TransportError> {
        lease
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let candidate_digest = request
            .candidate
            .compute_digest()
            .map_err(|_| TransportError::SessionFenced)?;
        if lease.authority_epoch != request.candidate.kernel_epoch
            || lease.state_fence
                != StateFence::new(request.candidate.kernel_epoch.clone(), request.generation)
        {
            return Err(TransportError::SessionFenced);
        }
        let activation = self
            .service
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .activation_receipt()
            .cloned()
            .ok_or(TransportError::SessionFenced)?;
        if activation.candidate_binding_digest != candidate_digest
            || activation.generation != request.generation
            || activation.authority_epoch != request.candidate.kernel_epoch
        {
            return Err(TransportError::SessionFenced);
        }
        let owner_ref = runtime_lease_handle(
            lease
                .obligation
                .obligation_refs
                .as_slice()
                .first()
                .ok_or(TransportError::SessionFenced)?
                .clone(),
        )?;
        if lease.obligation.obligation_refs.len() != 1 {
            return Err(TransportError::SessionFenced);
        }
        let observed = self.resolve_runtime_lease_owner(
            request,
            &owner_ref,
            None,
            Some(&lease.state_fence),
        )?;
        let canonical = &observed.admission;
        if lease.lease_id
            != eliot_kernel_service::expected_runtime_lease_id(
                &request.candidate,
                request.generation,
                canonical,
            )
            .map_err(|_| TransportError::SessionFenced)?
            || lease.scope_ref
                != format!("eliot-runtime-scope:v1:{}", lease.lease_id.trim_start_matches("eliot-runtime-lease:v1:"))
            || lease.obligation.holder != canonical.holder.as_str()
            || lease.obligation.reason != canonical.reason.as_str()
            || lease.obligation.required_runtime_branches
                != canonical
                    .required_runtime_branches
                    .iter()
                    .map(|value| value.as_str().to_owned())
                    .collect::<Vec<_>>()
            || lease.obligation.required_capabilities
                != canonical
                    .required_capabilities
                    .iter()
                    .map(|value| value.as_str().to_owned())
                    .collect::<Vec<_>>()
            || lease.obligation.obligation_refs
                != canonical
                    .obligation_refs
                    .iter()
                    .map(|value| value.as_str().to_owned())
                    .collect::<Vec<_>>()
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    fn resolve_runtime_lease_owner(
        &self,
        request: &KernelControlRequest,
        owner_ref: &PlatformHandle,
        expected: Option<&eliot_kernel_service::RuntimeLeaseOwnerAdmission>,
        expected_fence: Option<&StateFence>,
    ) -> Result<RuntimeLeaseOwnerObservation, TransportError> {
        let parsed = runtime_lease_owner_ref(owner_ref.as_str())?;
        let parsed_kind = runtime_lease_owner_kind(&parsed);
        if let Some(expected) = expected {
            if expected.owner_ref != *owner_ref {
                return Err(TransportError::SessionFenced);
            }
        }
        let ref_string = runtime_lease_owner_ref_string(&parsed);
        let state_fence = expected_fence.cloned().unwrap_or_else(|| {
            StateFence::new(
                request.candidate.kernel_epoch.clone(),
                request.generation,
            )
        });
        if state_fence.resource_generation != request.generation
            || !state_fence
                .authority_epoch
                .is_same_authority(&request.candidate.kernel_epoch)
        {
            return Err(TransportError::SessionFenced);
        }
        let mut owner_digest = None;
        let mut owner_fence_digest = None;
        let mut resource_binding_digest = None;
        let mut owner_kind = parsed_kind;
        let mut holder = None;
        let mut reason = None;
        let mut branches = Vec::new();
        let mut capabilities = Vec::new();
        let mut immutable_evidence = Vec::new();
        let mut renewal_evidence = Vec::new();
        let mut admitted_wait = false;
        let active;
        let renewable;
        match &parsed {
            RuntimeLeaseOwnerRef::HostRequest {
                operation_id,
                request_digest,
            } => {
                let operation_id = eliot_ors::OperationIdentity::new(operation_id.clone())
                    .map_err(|_| TransportError::SessionFenced)?;
                let record = self
                    .generation_gateway
                    .ors
                    .load_host_request(&operation_id, request_digest)
                    .map_err(|_| TransportError::SessionFenced)?
                    .ok_or(TransportError::SessionFenced)?;
                if record.operation_id != operation_id
                    || record.request_digest != *request_digest
                    || record.generation != request.generation.value()
                    || !record
                        .authority_epoch
                        .is_same_authority(&request.candidate.kernel_epoch)
                {
                    return Err(TransportError::SessionFenced);
                }
                runtime_lease_digest(&record.fence_digest)?;
                owner_fence_digest = Some(record.fence_digest.clone());
                owner_kind = if record.kind == eliot_ors::HostRequestKind::Activation {
                    eliot_kernel_service::RuntimeLeaseOwnerKind::Upgrade
                } else {
                    eliot_kernel_service::RuntimeLeaseOwnerKind::Session
                };
                let deadline_fresh = record.deadline_unix_ms > unix_ms();
                active = deadline_fresh && runtime_lease_host_request_active(record.state);
                renewable = active && matches!(
                    record.state,
                    eliot_ors::HostRequestState::Routed
                        | eliot_ors::HostRequestState::Submitted
                        | eliot_ors::HostRequestState::PossiblyEffected
                        | eliot_ors::HostRequestState::Unknown
                        | eliot_ors::HostRequestState::Reconciling
                );
                admitted_wait = matches!(
                    record.state,
                    eliot_ors::HostRequestState::Admitted
                        | eliot_ors::HostRequestState::PossiblyEffected
                        | eliot_ors::HostRequestState::Unknown
                        | eliot_ors::HostRequestState::Reconciling
                );
                owner_digest = Some(record.request_digest.clone());
                holder = Some(
                    record
                        .session_ref
                        .clone()
                        .or(record.task_ref.clone())
                        .unwrap_or(record.connection_ref.clone())
                        .as_str()
                        .to_owned(),
                );
                reason = Some(format!(
                    "host-request:{}",
                    runtime_lease_host_request_kind(record.kind)
                ));
                branches.extend(["kernel".to_owned(), "host-request".to_owned()]);
                capabilities.push(record.capability_ref.as_str().to_owned());
                immutable_evidence.extend([
                    format!("host-request-request:{}", record.request_digest),
                    format!("host-request-payload:{}", record.payload_digest),
                    format!("host-request-fence:{}", record.fence_digest),
                    format!("host-request-deadline:{}", record.deadline_unix_ms),
                ]);
                renewal_evidence.extend(immutable_evidence.iter().cloned());
                renewal_evidence.push(format!("host-request-state:{:?}", record.state));
                renewal_evidence.push(format!(
                    "host-request-result:{}",
                    record.result_digest.as_deref().unwrap_or("pending")
                ));
            }
            RuntimeLeaseOwnerRef::DoctorAttempt(identity) => {
                let identity = eliot_ors::OperationIdentity::new(identity.clone())
                    .map_err(|_| TransportError::SessionFenced)?;
                let record = self
                    .generation_gateway
                    .ors
                    .load_doctor_attempt(&identity)
                    .map_err(|_| TransportError::SessionFenced)?
                    .ok_or(TransportError::SessionFenced)?;
                if record.attempt_digest != identity
                    || record.generation != request.generation.value()
                    || record
                        .validate_against_epoch(&request.candidate.kernel_epoch)
                        .is_err()
                {
                    return Err(TransportError::SessionFenced);
                }
                runtime_lease_digest(&record.fence_digest)?;
                owner_fence_digest = Some(record.fence_digest.clone());
                let now_nanos = runtime_lease_now_nanos();
                let deadline_fresh = record.deadline_unix_nanos > now_nanos
                    && record.lease_expires_unix_nanos > now_nanos;
                active = deadline_fresh && runtime_lease_attempt_active(record.state);
                renewable = active && matches!(
                    record.state,
                    eliot_ors::DoctorAttemptState::EffectIntended
                        | eliot_ors::DoctorAttemptState::Unknown
                        | eliot_ors::DoctorAttemptState::Reconciling
                );
                admitted_wait = matches!(
                    record.state,
                    eliot_ors::DoctorAttemptState::Admitted
                        | eliot_ors::DoctorAttemptState::Unknown
                        | eliot_ors::DoctorAttemptState::Reconciling
                );
                let admission_digest = record
                    .admission_digest
                    .clone()
                    .ok_or(TransportError::SessionFenced)?;
                owner_digest = Some(admission_digest.clone());
                holder = Some(record.principal_ref.as_str().to_owned());
                reason = Some(record.operation_id.as_str().to_owned());
                branches.extend(["kernel".to_owned(), "doctor".to_owned()]);
                capabilities.push(record.component_ref.as_str().to_owned());
                immutable_evidence.extend([
                    format!("doctor-attempt-admission:{admission_digest}"),
                    format!("doctor-attempt-binding:{}", record.binding_digest),
                    format!("doctor-attempt-fence:{}", record.fence_digest),
                    format!("doctor-attempt-deadline:{}", record.deadline_unix_nanos),
                    format!(
                        "doctor-attempt-lease-expiry:{}",
                        record.lease_expires_unix_nanos
                    ),
                ]);
                renewal_evidence.extend(immutable_evidence.iter().cloned());
                renewal_evidence.push(format!("doctor-attempt-state:{:?}", record.state));
                renewal_evidence.push(format!(
                    "doctor-attempt-admitted-at:{}",
                    record.admitted_at_unix_nanos.unwrap_or_default()
                ));
            }
            RuntimeLeaseOwnerRef::DoctorEffect(identity) => {
                let identity = eliot_ors::OperationIdentity::new(identity.clone())
                    .map_err(|_| TransportError::SessionFenced)?;
                let record = self
                    .generation_gateway
                    .ors
                    .load_doctor_effect(&identity)
                    .map_err(|_| TransportError::SessionFenced)?
                    .ok_or(TransportError::SessionFenced)?;
                let attempt_identity = eliot_ors::OperationIdentity::new(
                    record.attempt_digest.clone(),
                )
                .map_err(|_| TransportError::SessionFenced)?;
                let attempt = self
                    .generation_gateway
                    .ors
                    .load_doctor_attempt(&attempt_identity)
                    .map_err(|_| TransportError::SessionFenced)?
                    .ok_or(TransportError::SessionFenced)?;
                if record.effect_digest != identity
                    || attempt.generation != request.generation.value()
                    || attempt
                        .validate_against_epoch(&request.candidate.kernel_epoch)
                        .is_err()
                {
                    return Err(TransportError::SessionFenced);
                }
                runtime_lease_digest(&attempt.fence_digest)?;
                owner_fence_digest = Some(attempt.fence_digest.clone());
                let now_nanos = runtime_lease_now_nanos();
                let attempt_fresh = attempt.deadline_unix_nanos > now_nanos
                    && attempt.lease_expires_unix_nanos > now_nanos;
                active = attempt_fresh
                    && runtime_lease_attempt_active(attempt.state)
                    && runtime_lease_effect_active(record.state);
                renewable = active;
                admitted_wait = active;
                owner_digest = Some(record.intent_digest.clone());
                holder = Some(record.attempt_digest.clone());
                reason = Some(record.operation_id.as_str().to_owned());
                branches.extend(["kernel".to_owned(), "effect".to_owned()]);
                capabilities.push("external-effect".to_owned());
                immutable_evidence.extend([
                    format!("doctor-effect-intent:{}", record.intent_digest),
                    format!("doctor-effect-attempt:{}", record.attempt_digest),
                    format!("doctor-effect-operation:{}", record.operation_id.as_str()),
                    format!("doctor-effect-fence:{}", attempt.fence_digest),
                    format!("doctor-effect-deadline:{}", attempt.deadline_unix_nanos),
                    format!(
                        "doctor-effect-lease-expiry:{}",
                        attempt.lease_expires_unix_nanos
                    ),
                ]);
                renewal_evidence.extend(immutable_evidence.iter().cloned());
                renewal_evidence.push(format!("doctor-effect-state:{:?}", record.state));
            }
            RuntimeLeaseOwnerRef::NativeWorkerClaim(identity) => {
                let identity = eliot_ors::OperationIdentity::new(identity.clone())
                    .map_err(|_| TransportError::SessionFenced)?;
                let record = self
                    .generation_gateway
                    .ors
                    .load_native_worker_claim(&identity)
                    .map_err(|_| TransportError::SessionFenced)?
                    .ok_or(TransportError::SessionFenced)?;
                if record.claim_id != identity {
                    return Err(TransportError::SessionFenced);
                }
                // Native-worker ORS keeps the worker-generation scalar only as
                // a projection.  It is not the Kernel ResourceGeneration and
                // is never used as the authority check.  The current full
                // registration fence/resource projection is bound below;
                // the scalar is checked only for consistency with that owner
                // record after the full fence digest matches.
                runtime_lease_digest(&record.fence_digest)?;
                runtime_lease_digest(&record.resource_envelope_digest)?;
                owner_fence_digest = Some(record.fence_digest.clone());
                resource_binding_digest = Some(record.resource_envelope_digest.clone());
                if record.authority_epoch != state_fence.authority_epoch.sequence.get() {
                    return Err(TransportError::SessionFenced);
                }
                let deadline_fresh = record.deadline_unix_ms > unix_ms();
                active = deadline_fresh && runtime_lease_claim_active(record.state);
                renewable = active && matches!(
                    record.state,
                    eliot_ors::NativeWorkerClaimState::Ready
                        | eliot_ors::NativeWorkerClaimState::Active
                        | eliot_ors::NativeWorkerClaimState::Cancelling
                        | eliot_ors::NativeWorkerClaimState::Submitted
                        | eliot_ors::NativeWorkerClaimState::Unknown
                        | eliot_ors::NativeWorkerClaimState::Reconciling
                );
                admitted_wait = matches!(
                    record.state,
                    eliot_ors::NativeWorkerClaimState::Admitted
                        | eliot_ors::NativeWorkerClaimState::Unknown
                        | eliot_ors::NativeWorkerClaimState::Reconciling
                );
                owner_digest = Some(record.binding_digest.clone());
                holder = Some(record.parent_job_id.as_str().to_owned());
                reason = Some(record.operation_id.as_str().to_owned());
                branches.extend(["kernel".to_owned(), "native-worker".to_owned()]);
                capabilities.push(record.route_class.as_str().to_owned());
                immutable_evidence.extend([
                    format!("native-claim-binding:{}", record.binding_digest),
                    format!("native-claim-request:{}", record.request_digest),
                    format!("native-claim-fence:{}", record.fence_digest),
                    format!(
                        "native-claim-registration:{}",
                        record.registration_id.as_str()
                    ),
                    format!(
                        "native-claim-resource:{}",
                        record.resource_envelope_digest
                    ),
                    format!("native-claim-deadline:{}", record.deadline_unix_ms),
                ]);
                renewal_evidence.extend(immutable_evidence.iter().cloned());
                renewal_evidence.push(format!("native-claim-state:{:?}", record.state));
            }
        }
        let owner_digest = owner_digest.ok_or(TransportError::SessionFenced)?;
        let owner_fence_digest = owner_fence_digest.ok_or(TransportError::SessionFenced)?;
        let expected_fence_digest = runtime_lease_state_fence_digest(&state_fence)?;
        if owner_fence_digest != expected_fence_digest {
            return Err(TransportError::SessionFenced);
        }
        let holder = runtime_lease_handle(holder.ok_or(TransportError::SessionFenced)?)?;
        let reason = runtime_lease_handle(reason.ok_or(TransportError::SessionFenced)?)?;
        let required_runtime_branches = runtime_lease_handles(branches)?;
        let required_capabilities = runtime_lease_handles(capabilities)?;
        let obligation_ref = runtime_lease_handle(ref_string)?;
        let evidence_refs = runtime_lease_handles(immutable_evidence)?;
        let renewal_evidence_refs = runtime_lease_handles(renewal_evidence.clone())?;
        let owner_admission = eliot_kernel_service::RuntimeLeaseOwnerAdmission {
            kind: owner_kind,
            owner_ref: obligation_ref.clone(),
            admission_digest: owner_digest.clone(),
            fence_digest: owner_fence_digest.clone(),
            resource_binding_digest,
        };
        if let Some(expected) = expected {
            if expected.kind != owner_kind
                || expected.admission_digest != owner_digest
                || expected.fence_digest != owner_fence_digest
                || expected.resource_binding_digest != owner_admission.resource_binding_digest
            {
                return Err(TransportError::SessionFenced);
            }
        }
        let admission = RuntimeLeaseAdmission {
            owner_admission: Some(owner_admission),
            holder,
            reason,
            required_runtime_branches,
            required_capabilities,
            obligation_refs: vec![obligation_ref],
            evidence_refs,
            state_fence,
        };
        admission
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(RuntimeLeaseOwnerObservation {
            admission,
            renewal_evidence_refs,
            renewal_evidence,
            admitted_wait,
            active,
            renewable,
        })
    }

    fn validate_runtime_lease_admission_projection(
        &self,
        request: &KernelControlRequest,
        supplied: &RuntimeLeaseAdmission,
    ) -> Result<RuntimeLeaseOwnerObservation, TransportError> {
        let owner = supplied
            .owner_admission
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let owner_ref = &owner.owner_ref;
        let observed = self.resolve_runtime_lease_owner(
            request,
            owner_ref,
            Some(owner),
            Some(&supplied.state_fence),
        )?;
        let canonical = &observed.admission;
        if supplied.holder != canonical.holder
            || supplied.reason != canonical.reason
            || supplied.required_runtime_branches != canonical.required_runtime_branches
            || supplied.required_capabilities != canonical.required_capabilities
            || supplied.obligation_refs != canonical.obligation_refs
            || supplied.evidence_refs != canonical.evidence_refs
            || supplied.state_fence != canonical.state_fence
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(observed)
    }

    fn acquire_runtime_lease(
        &self,
        request: &KernelControlRequest,
        admission: &RuntimeLeaseAdmission,
    ) -> Result<RuntimeLease, TransportError> {
        if self
            .service_state()
            .map_err(|_| TransportError::SessionFenced)?
            != KernelServiceState::Ready
        {
            return Err(TransportError::SessionFenced);
        }
        admission
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let observed = self.validate_runtime_lease_admission_projection(request, admission)?;
        if !observed.active {
            return Err(TransportError::SessionFenced);
        }
        let canonical = &observed.admission;
        let expected_lease_id = eliot_kernel_service::expected_runtime_lease_id(
            &request.candidate,
            request.generation,
            canonical,
        )
        .map_err(|_| TransportError::SessionFenced)?;

        // The stable owner identity is the replay key.  Read it before
        // generating any new timestamps so a lost first response returns the
        // original committed row instead of trying to replace it.
        if let Some(existing) = self
            .generation_gateway
            .ors
            .load_current_runtime_lease(&expected_lease_id)
            .map_err(|_| TransportError::SessionFenced)?
        {
            self.validate_runtime_lease_owner(request, &existing)?;
            if existing.state != LeaseState::Active || existing.lease_id != expected_lease_id {
                return Err(TransportError::SessionFenced);
            }
            if existing.obligation.expires_at_ms <= unix_ms() {
                // A stable acquire identity remains idempotent, but an
                // elapsed row is no longer authority.  Reconcile the
                // durable row before rejecting the replay so the caller can
                // observe the owner-controlled terminal path instead of
                // receiving an expired lease labelled Active.
                self.reconcile_runtime_lease(
                    request,
                    &RuntimeLeaseReconcile {
                        lease_id: existing.lease_id.clone(),
                        state_fence: existing.state_fence.clone(),
                    },
                )?;
                return Err(TransportError::SessionFenced);
            }
            return Ok(existing);
        }

        let issued_at_ms = unix_ms();
        let expires_at_ms = issued_at_ms
            .checked_add(RUNTIME_LEASE_TTL_MS)
            .ok_or(TransportError::SessionFenced)?;
        let renew_before_ms = issued_at_ms
            .checked_add(RUNTIME_LEASE_RENEW_BEFORE_MS)
            .ok_or(TransportError::SessionFenced)?;
        let expected = eliot_kernel_service::expected_runtime_lease(
            &request.candidate,
            request.generation,
            canonical,
            issued_at_ms,
            expires_at_ms,
            renew_before_ms,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let acquired = self
            .generation_gateway
            .ors
            .acquire_runtime_lease(&expected)
            .map_err(|_| TransportError::SessionFenced)?;
        let readback = self
            .generation_gateway
            .ors
            .load_current_runtime_lease(&expected.lease_id)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::SessionFenced)?;
        self.validate_runtime_lease_owner(request, &readback)?;
        if acquired != expected || readback != acquired || readback.lease_id != expected_lease_id {
            return Err(TransportError::SessionFenced);
        }
        Ok(readback)
    }

    fn renew_runtime_lease(
        &self,
        request: &KernelControlRequest,
        renewal: &RuntimeLeaseRenewal,
    ) -> Result<RuntimeLease, TransportError> {
        renewal
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let current = self
            .generation_gateway
            .ors
            .load_current_runtime_lease(&renewal.lease_id)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::SessionFenced)?;
        self.validate_runtime_lease_owner(request, &current)?;
        let owner_ref = runtime_lease_handle(
            current
            .obligation
            .obligation_refs
            .first()
            .ok_or(TransportError::SessionFenced)?
            .clone(),
        )?;
        let observed = self.resolve_runtime_lease_owner(
            request,
            &owner_ref,
            None,
            Some(&current.state_fence),
        )?;
        if !observed.active || !(observed.renewable || observed.admitted_wait) {
            return Err(TransportError::SessionFenced);
        }
        if current.revision != renewal.expected_revision
            || current.state_fence != renewal.state_fence
            || current.state != LeaseState::Active
            || unix_ms() < current.obligation.renew_before_ms
        {
            return Err(TransportError::SessionFenced);
        }
        if observed.renewal_evidence.is_empty()
            || (!observed.admitted_wait
                && observed.renewal_evidence == current.obligation.renewal_evidence)
        {
            return Err(TransportError::SessionFenced);
        }
        let now_ms = unix_ms();
        let expires_at_ms = now_ms
            .checked_add(RUNTIME_LEASE_TTL_MS)
            .ok_or(TransportError::SessionFenced)?;
        let renew_before_ms = now_ms
            .checked_add(RUNTIME_LEASE_RENEW_BEFORE_MS)
            .ok_or(TransportError::SessionFenced)?;
        let renewed = self
            .generation_gateway
            .ors
            .renew_runtime_lease(
                &renewal.lease_id,
                renewal.expected_revision,
                &renewal.state_fence,
                observed.renewal_evidence,
                now_ms,
                expires_at_ms,
                renew_before_ms,
            )
            .map_err(|_| TransportError::SessionFenced)?;
        self.validate_runtime_lease_owner(request, &renewed)?;
        Ok(renewed)
    }

    fn transition_runtime_lease(
        &self,
        request: &KernelControlRequest,
        terminal: &RuntimeLeaseTerminal,
        next_state: LeaseState,
    ) -> Result<RuntimeLease, TransportError> {
        let current = self
            .generation_gateway
            .ors
            .load_current_runtime_lease(&terminal.lease_id)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::SessionFenced)?;
        self.validate_runtime_lease_owner(request, &current)?;
        if current.revision != terminal.expected_revision
            || current.state_fence != terminal.state_fence
        {
            return Err(TransportError::SessionFenced);
        }
        if next_state == LeaseState::Expired && unix_ms() < current.obligation.expires_at_ms {
            return Err(TransportError::SessionFenced);
        }
        let evidence = terminal
            .evidence_refs
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect();
        let transitioned = self
            .generation_gateway
            .ors
            .transition_runtime_lease(
                &terminal.lease_id,
                terminal.expected_revision,
                &terminal.state_fence,
                next_state,
                terminal.disposition.as_str().to_owned(),
                evidence,
            )
            .map_err(|_| TransportError::SessionFenced)?;
        self.validate_runtime_lease_owner(request, &transitioned)?;
        Ok(transitioned)
    }

    fn reconcile_runtime_lease(
        &self,
        request: &KernelControlRequest,
        reconcile: &RuntimeLeaseReconcile,
    ) -> Result<Option<RuntimeLease>, TransportError> {
        let current = self
            .generation_gateway
            .ors
            .load_current_runtime_lease(&reconcile.lease_id)
            .map_err(|_| TransportError::SessionFenced)?;
        let Some(current) = current else {
            return Ok(None);
        };
        if current.state_fence != reconcile.state_fence {
            return Err(TransportError::SessionFenced);
        }
        // Reconciliation may transition an expired row, so candidate and
        // owner binding must be proved before ORS is allowed to mutate it.
        self.validate_runtime_lease_owner(request, &current)?;
        let evidence = vec![format!("kernel-reconcile:{}", request.payload_digest)];
        let lease = self
            .generation_gateway
            .ors
            .reconcile_runtime_lease(
                &reconcile.lease_id,
                &reconcile.state_fence,
                evidence,
                unix_ms(),
            )
            .map_err(|_| TransportError::SessionFenced)?;
        if let Some(lease) = &lease {
            self.validate_runtime_lease_owner(request, lease)?;
        }
        Ok(lease)
    }

    /// Consumes one authenticated Host startup-evidence carrier. Host owns
    /// probe truth; Kernel owns only the I1.11 cursor. The request boundary
    /// validates candidate/fence binding before this method is reached.
    fn consume_host_startup_evidence(
        &self,
        evidence: &HostStartupEvidence,
    ) -> Result<(), TransportError> {
        // Keep the consumer boundary explicit if another authenticated
        // composition path reuses this helper without `KernelControlRequest`.
        evidence
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        // Record each observed probe independently: an absent Blob manifest
        // never becomes a fabricated step-4 success.
        self.record_startup_evidence(1)
            .map_err(|_| TransportError::SessionFenced)?;
        self.record_startup_evidence(2)
            .map_err(|_| TransportError::SessionFenced)?;
        if evidence.blob_manifest_digest.is_some() {
            self.record_startup_evidence(4)
                .map_err(|_| TransportError::SessionFenced)?;
        }
        Ok(())
    }

    /// Returns the runtime's protected-control capacity.
    ///
    /// Diagnostic read (F-LOG-KERNEL-4, #903): the observed count is emitted
    /// as a bounded nonsecret field; the reserve itself is never acquired,
    /// released, or resized here.
    #[must_use]
    pub fn control_capacity(&self) -> usize {
        let capacity = self
            .runtime
            .available_capacity(eliot_runtime::ExecutionClass::ProtectedControl);
        observe_control_capacity(capacity);
        capacity
    }

    /// Requests shutdown without starting a second lifecycle owner.
    ///
    /// Records the Kernel-owned I14.23 drain intent (persisted, resumable)
    /// before closing runtime admission, so a later `shutdown()` observes
    /// the request even when admission closure wins the race.
    #[must_use]
    pub fn request_shutdown(&self) -> bool {
        let _ = coordinator_for(&self.work_root).request_shutdown();
        self.runtime.shutdown_handle().request()
    }
}

#[cfg(test)]
mod control_plane_diagnostics_tests {
    //! F-LOG-KERNEL-4 (#903) focused diagnostics proof: stable terminal
    //! codes for the transition gateway and the authenticated request
    //! boundary. Both mappers emit variant vocabulary only; payloads,
    //! digests, and peer material never reach the sink.

    use super::*;

    fn host_startup_evidence(blob_manifest_digest: Option<&str>) -> HostStartupEvidence {
        let epoch = eliot_contracts::EpochId::new(
            eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("test lineage"),
            std::num::NonZeroU64::new(1).expect("test epoch"),
        )
        .expect("test epoch");
        HostStartupEvidence {
            candidate_digest: "ab".repeat(32),
            state_fence: StateFence::new(
                epoch,
                eliot_contracts::ResourceGeneration::new(1).expect("test generation"),
            ),
            host_record_checksum: eliot_platform::PlatformHandle::new("journal-checksum-1")
                .expect("journal handle"),
            artifact_registry_digest: eliot_platform::PlatformHandle::new("registry-manifest-1")
                .expect("registry handle"),
            scm_watchdog_observation_digest: eliot_platform::PlatformHandle::new(format!(
                "host-scm-watchdog:4242:987654321:{}",
                "cd".repeat(32)
            ))
            .expect("SCM handle"),
            blob_manifest_digest: blob_manifest_digest
                .map(|digest| eliot_platform::PlatformHandle::new(digest).expect("Blob handle")),
            evidence_refs: Vec::new(),
        }
    }

    #[test]
    fn host_evidence_records_only_observed_probe_steps() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-host-startup-consumer-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");

        kernel
            .consume_host_startup_evidence(&host_startup_evidence(None))
            .expect("Host steps 1 and 2 should be recorded");
        kernel
            .record_startup_evidence(3)
            .expect("step 3 test evidence");
        assert_eq!(
            kernel
                .startup_status(GovernanceProfile::minimal())
                .completed_step,
            3,
            "absent Blob probe must leave step 4 unobserved"
        );

        let second_root = root.join("with-blob");
        std::fs::create_dir_all(&second_root).expect("second test work root");
        let second = KernelComposition::new(KernelConfig::new(&second_root))
            .expect("second kernel composition");
        second
            .consume_host_startup_evidence(&host_startup_evidence(Some(
                "host-blob-manifest:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
            )))
            .expect("Host steps including Blob should be recorded");
        second
            .record_startup_evidence(3)
            .expect("step 3 test evidence");
        assert_eq!(
            second
                .startup_status(GovernanceProfile::minimal())
                .completed_step,
            4,
            "present Blob probe should advance step 4 after its predecessor"
        );

        drop(second);
        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn probe_watchdog_branch_requires_exact_nonzero_epoch() {
        assert!(verify_probe_watchdog_branch(7, 7).is_ok());
        assert_eq!(
            verify_probe_watchdog_branch(7, 8),
            Err(TransportError::SessionFenced)
        );
        assert_eq!(
            verify_probe_watchdog_branch(0, 7),
            Err(TransportError::SessionFenced)
        );
        assert_eq!(
            verify_probe_watchdog_branch(7, 0),
            Err(TransportError::SessionFenced)
        );
    }

    #[test]
    fn control_diagnostics_terminal_codes_are_stable() {
        // Transition gateway codes: one fixed code per service failure
        // variant, even when the payload carries a secret-like canary.
        assert_eq!(
            control_transition_terminal_code(&KernelServiceError::GenerationFenced),
            "CONTROL_GENERATION_FENCED"
        );
        assert_eq!(
            control_transition_terminal_code(&KernelServiceError::ReadinessNotProven),
            "CONTROL_READINESS_NOT_PROVEN"
        );
        assert_eq!(
            control_transition_terminal_code(&KernelServiceError::MissingContainmentEvidence),
            "CONTROL_MISSING_CONTAINMENT"
        );
        assert_eq!(
            control_transition_terminal_code(&KernelServiceError::RestartBudgetExhausted),
            "CONTROL_RESTART_BUDGET_EXHAUSTED"
        );
        assert_eq!(
            control_transition_terminal_code(&KernelServiceError::ControlReserveExhausted),
            "CONTROL_RESERVE_EXHAUSTED"
        );
        assert_eq!(
            control_transition_terminal_code(&KernelServiceError::Platform(
                "token=control-canary".to_owned()
            )),
            "CONTROL_PLATFORM"
        );

        // Request boundary codes: every transport failure keeps its own
        // request-operation code; the fenced admission path keeps the exact
        // typed denial without request material.
        assert_eq!(
            control_request_terminal_code(&TransportError::SessionFenced),
            "control_fenced"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::PeerIdentityUnavailable),
            "control_peer_unavailable"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::UnauthenticatedPeer),
            "control_unauthenticated_peer"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::Timeout),
            "control_timeout"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::Cancelled),
            "control_cancelled"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::UnknownOutcome),
            "control_unknown_outcome"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::Backpressure),
            "control_backpressure"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::RegistryFull),
            "control_registry_full"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::Io("pipe-canary".to_owned())),
            "control_io"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::PlanGap {
                dependency: "dep",
                reason: "reason",
            }),
            "control_plan_gap"
        );
    }
}
