//! Kernel control-plane transition and authenticated request handling.
//!
//! Architecture traceability:
//! - `A13.2` (`docs/architecture/A13-02-kernel-and-failure-domains.md`) keeps
//!   Kernel as the lifecycle and failure boundary for this control path.
//! - `A13.5` (`docs/architecture/A13-05-bounded-resources-and-control-reserve.md`)
//!   binds control work to the existing protected-control reserve; this module
//!   exposes its capacity without creating a second budget.
//! - The R1 Kernel runtime layer
//!   (`docs/architecture/I-PREFACE-04-runtime-layer-model.md`) keeps
//!   front-door request admission and lifecycle transitions in Kernel while
//!   service semantics stay behind the existing `KernelService` gateway.
//! - `I1.5`
//!   (`docs/architecture/I01-05-demand-start-observable-use-supervision-and-idle-shutdown.md`)
//!   and `I14.13` (`docs/architecture/I14-13-idle-drain-and-cancellation.md`)
//!   constrain shutdown to the existing runtime signal and drain owners.
//! - `I14.23` (`docs/architecture/I14-23-safe-shutdown.md`) leaves the complete
//!   cooperative shutdown sequence in `KernelComposition::shutdown`.
//!
//! The implementation remains an ordinary module so the composition root keeps
//! its public API while the control-plane lifecycle gateway has a bounded home.

use super::*;

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
        TransportError::Backpressure | TransportError::AttributedBackpressure(_) => {
            "control_backpressure"
        }
        TransportError::Timeout => "control_timeout",
        TransportError::Cancelled => "control_cancelled",
        TransportError::InvalidPipeName => "control_invalid_pipe",
        TransportError::UnknownOutcome => "control_unknown_outcome",
        TransportError::Io(_) => "control_io",
        TransportError::PlanGap { .. } => "control_plan_gap",
        TransportError::UnknownRequest => "control_unknown_request",
        TransportError::IdentityConflict => "control_identity_conflict",
        TransportError::LegacyCorrelationUnresolved => "control_legacy_correlation_unresolved",
        TransportError::RegistryFull => "control_registry_full",
    }
}

/// Preserves the original failure class until the request boundary chooses
/// the sole terminal code for this operation.
enum ControlRequestFailure {
    Transport(TransportError),
    Transition(KernelServiceError),
}

impl From<TransportError> for ControlRequestFailure {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
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

impl KernelComposition {
    /// Takes exclusive Kernel ownership of one installation/activation contour.
    ///
    /// I14.16 step 7: the replacement Kernel acquires the exclusive owner
    /// object for the exact contour Host bound to it, and Host refuses to mark
    /// the candidate active unless this object exists and is not creatable by
    /// anyone else. The object is created at the candidate `Reconcile` - the
    /// first point where this process learns its own contour, and still inside
    /// the zero-authority shadow phase - and is held for the process lifetime.
    /// A repeated reconcile of a different contour in the same process is
    /// refused rather than silently keeping the previous owner.
    #[cfg(windows)]
    pub(crate) fn acquire_kernel_owner(
        &self,
        installation: &PlatformHandle,
        activation: &PlatformHandle,
    ) -> Result<(), eliot_platform_windows::KernelOwnerLeaseError> {
        // A poisoned gate still has to be recovered: refusing here would leave
        // the contour's owner unrecorded while this process keeps running.
        let mut owner = self
            .kernel_owner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(held) = owner.as_ref() {
            if !held.is_for(installation, activation) {
                return Err(eliot_platform_windows::KernelOwnerLeaseError::ExistingObject);
            }
            let capability = held.owner_capability();
            // Proves this process still owns the object right now; a released
            // or dropped lease fails closed here.
            let _live = capability
                .live_guard()
                .map_err(|_| eliot_platform_windows::KernelOwnerLeaseError::ExistingObject)?;
            return Ok(());
        }
        *owner = Some(eliot_platform_windows::KernelOwnerLease::acquire(
            installation,
            activation,
        )?);
        Ok(())
    }

    /// Applies one lifecycle command through the sole Kernel transition gateway.
    ///
    /// Diagnostic wrapper (F-LOG-KERNEL-4, #903): exactly one terminal is
    /// emitted per failed transition; the admitted state versus the failure
    /// record stay distinct, and no command or error material is logged.
    pub fn apply_control(
        &self,
        command: KernelControlCommand,
    ) -> Result<KernelServiceState, KernelServiceError> {
        self.apply_control_with_terminal(command, true)
    }

    fn apply_control_with_terminal(
        &self,
        command: KernelControlCommand,
        emit_terminal: bool,
    ) -> Result<KernelServiceState, KernelServiceError> {
        observe_control("kernel.control.transition_requested", "attempt");
        match self.apply_control_inner(command) {
            Ok(state) => {
                observe_control("kernel.control.transition_committed", "success");
                Ok(state)
            }
            Err(error) => {
                observe_control("kernel.control.transition_failed", "rejected");
                if emit_terminal {
                    super::kernel_diagnostics::observe_terminal_error(
                        control_transition_terminal_code(&error),
                    );
                }
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
    /// emitted per failed request. A nested transition's preserved cause
    /// selects its stable code; other failures use the request error code.
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
                let (terminal_code, transport_error) = match error {
                    ControlRequestFailure::Transport(error) => {
                        (control_request_terminal_code(&error), error)
                    }
                    ControlRequestFailure::Transition(error) => (
                        control_transition_terminal_code(&error),
                        TransportError::SessionFenced,
                    ),
                };
                super::kernel_diagnostics::observe_terminal_error(terminal_code);
                Err(transport_error)
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
    ) -> Result<KernelControlResponse, ControlRequestFailure> {
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
            return Err(TransportError::SessionFenced.into());
        }
        #[cfg(windows)]
        self.validate_candidate_process_binding(&request.candidate)
            .map_err(|_| TransportError::SessionFenced)?;
        // I18.53 ACT-4 / I1.5 (#1918): every authenticated request repeats the
        // exact nonce-free candidate binding so a reconnect cannot silently
        // inherit stale Host, process, Job, generation, or pipe identity. This
        // is the single typed place where the pre-suspend identity families
        // are revalidated against live Kernel-observed state: a resume that
        // presents a stale PID, pipe, authority epoch, `UserBroker`
        // registration or lease identity is fenced here, and the stale
        // families are recorded as the ACT-4 coverage gap. It runs before any
        // fence check below, so a stale identity is refused before it can
        // reach the service, the supervision evidence, or the activation
        // contour. The one family whose verdict this gate owns rather than
        // reads from the contract — `Lease` — admits a presented lease only
        // when the Kernel's own lease authority proves that exact head active
        // and unexpired; every other lease outcome, including one that cannot be
        // read at all, is refused, and `ResumeLeaseObservation` states that rule.
        //
        // Running first does not make it stricter than the fences below it.
        // The `Epoch` and `Broker` families admit only the fenced-forward
        // advances those fences already apply, so a legitimate `Reconcile`
        // epoch or activation-generation advance is never refused here on the
        // way to being admitted by the fence itself; the remaining four
        // families are strict comparisons in both directions.
        self.revalidate_activation_resume_identities(&request, peer)?;
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
                return Err(TransportError::SessionFenced.into());
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
        // I1.5 (#1750): a new candidate activation contour invalidates the
        // recorded independent-supervision evidence. The previous observation
        // belonged to the previous activation generation, host epoch, and
        // Watchdog epoch, so it is withdrawn here and can only be re-established
        // by a new Host observation of the live Watchdog branch under this
        // contour. This runs before any supervised readiness is published and
        // before the new contour is applied.
        if matches!(
            request.command,
            KernelControlCommand::Activate(_) | KernelControlCommand::ReconcileActivation(_)
        ) {
            self.revoke_supervision_evidence()
                .map_err(|_| TransportError::SessionFenced)?;
        }
        if let KernelControlCommand::ReportHostStartupEvidence(evidence) = &request.command {
            // I1.5/A8.1: this carrier is the one owner-correct route by which a
            // Host-observed Watchdog branch reaches Kernel. Host just
            // revalidated the live SCM Watchdog incarnation (bound PID/start
            // pair plus image bytes equal to the approved Watchdog artifact);
            // Kernel binds that observation to the presented candidate contour
            // and only then marks the I1.11 supervision step. Without that
            // step there is no supervised health projection and no
            // Material/Critical admission.
            #[cfg(windows)]
            {
                let target =
                    StateFence::new(request.candidate.kernel_epoch.clone(), request.generation);
                self.admit_host_observed_watchdog_branch(evidence, &request.candidate, &target)
                    .map_err(|_| TransportError::SessionFenced)?;
            }
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
                return Err(TransportError::SessionFenced.into());
            }
        }
        // I14.23 wake/attach race: a new activation arriving before the
        // `DrainCommit` linearization point cancels the drain and proceeds;
        // after linearization it cannot reuse the drained generation (the
        // service independently fences `Activate` from `Draining`) and must
        // re-establish a fresh generation through the reconcile path.
        if matches!(&request.command, KernelControlCommand::Activate(_)) {
            // The activation generation this request presents, taken from the
            // request's own authenticated candidate contour — the same
            // `SupervisionJournalEpoch` identity the `Broker` family compares
            // at `resume_broker_is_presented_as_current`, and the same domain
            // the drain recorded the generation it fenced in. Presenting the
            // fenced generation is a stale wake (`RejectStale`); presenting a
            // different one is a new authority being established and is queued
            // for the next generation (`QueueNextGeneration`). Both fence the
            // old authority through `fences_old_authority` below, so the
            // enforcement outcome is unchanged; what the compared value buys is
            // that the post-linearization verdict is now decided against the
            // generation the drain actually fenced instead of a local drain
            // correlation id no request can present.
            let presented_activation_generation = request
                .candidate
                .supervision_incarnation
                .activation_generation
                .clone();
            let disposition = coordinator_for(&self.work_root)
                .and_then(|coordinator| {
                    coordinator.on_activate_request(&presented_activation_generation)
                })
                .map_err(|_| TransportError::SessionFenced)?;
            observe_control(
                "kernel.control.drain_disposition_observed",
                disposition_code(disposition),
            );
            if disposition.fences_old_authority() {
                return Err(TransportError::SessionFenced.into());
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
                            return Err(TransportError::SessionFenced.into());
                        }
                        let receipt = store_rebind_receipt_from_ors_record(
                            &record,
                            &request.candidate.kernel_epoch,
                        )
                        .map_err(|_| TransportError::SessionFenced)?;
                        self.verify_store_rebind_publication_complete(&receipt)?;
                        // A reconciled commit resolves the matching drain-gate
                        // receipt when a shutdown is waiting on it.
                        coordinator_for(&self.work_root)
                            .and_then(|coordinator| {
                                coordinator.resolve_pending_receipt(&format!(
                                    "store-rebind:{}",
                                    query.operation_id.as_str()
                                ))
                            })
                            .map_err(|_| TransportError::SessionFenced)?;
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
                                coordinator_for(&self.work_root)
                                    .and_then(|coordinator| {
                                        coordinator.resolve_pending_receipt(&format!(
                                            "store-rebind:{}",
                                            query.operation_id.as_str()
                                        ))
                                    })
                                    .map_err(|_| TransportError::SessionFenced)?;
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
                                    return Err(TransportError::SessionFenced.into());
                                }
                                let receipt = store_rebind_receipt_from_ors_record(
                                    &after,
                                    &request.candidate.kernel_epoch,
                                )
                                .map_err(|_| TransportError::SessionFenced)?;
                                self.verify_store_rebind_publication_complete(&receipt)?;
                                // A reconciled commit resolves the matching
                                // drain-gate receipt when a shutdown waits.
                                coordinator_for(&self.work_root)
                                    .and_then(|coordinator| {
                                        coordinator.resolve_pending_receipt(&format!(
                                            "store-rebind:{}",
                                            query.operation_id.as_str()
                                        ))
                                    })
                                    .map_err(|_| TransportError::SessionFenced)?;
                                Some(receipt)
                            }
                            _ => return Err(TransportError::SessionFenced.into()),
                        }
                    }
                    Some(_) => return Err(TransportError::SessionFenced.into()),
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
            // I1.5 (#1750), I1.11 steps 1/11: this probe may not author a
            // ready receipt — and therefore may not publish any
            // supervised-readiness claim — unless the independent Watchdog
            // branch verifies from a CURRENT owner observation bound to this
            // contour and to the exact consumer State Fence.
            //
            // This is the production gate main had here and the branch dropped.
            // The dropped predicate was a lease-derived watchdog-epoch
            // equality: two bookkeeping `u64`s on the renewed ORS head, which
            // stay equal while Watchdog is stopped, replaced or wedged, so it
            // could admit a contour whose branch had never been observed. The
            // replacement requires an independent Watchdog observation bound to
            // THIS contour and to the exact consumer State Fence and still
            // inside its own finite validity interval (only `HostStartupEvidence`
            // can record one, and only after Host revalidated the PID/start pair
            // against the live OS and the live image bytes against the approved
            // Watchdog artifact), plus the whole supervised-branch conjunction.
            //
            // What this gate establishes, precisely: it refuses every case the
            // dropped lease-derived equality refused, and it additionally
            // refuses every case in which no current independent observation is
            // bound to this contour and fence — including one that has aged out
            // of its validity interval. It does NOT establish that it refuses a
            // Watchdog which stopped, was replaced or wedged after the last
            // observation while that observation is still inside its validity
            // interval. The evidence these predicates consume is the owner's
            // observation; a contradiction or an expiry is what narrows the
            // claim. See `admit_probe_watchdog_branch`.
            //
            // The target fence is read from the freshly renewed,
            // signature-verified head's own binding rather than rebuilt from
            // the request, so this gate cannot manufacture authority out of a
            // request field; the join clauses then bind that head back to the
            // presented candidate. A refusal surfaces as degraded readiness
            // instead of supervised health.
            self.admit_probe_watchdog_branch(
                &request.candidate,
                &renewed_head.record.binding.state_fence,
            )
            .map_err(|_| TransportError::SessionFenced)?;
        }
        #[cfg(windows)]
        if is_probe && let Some((renewed_head, live_receipt)) = supervision_publication.as_ref() {
            // I1.5 W4 (#1751): the probe that just renewed supervision is
            // fresh observable evidence for the runtime-lease tick beside
            // the issuance site below. Past-due rows for this fence reach
            // their terminal revision through the owner transition, and
            // live rows held by this activation renew from this probe's
            // renewed head and live receipt. A failed tick fails the probe
            // closed rather than serving readiness over stale rows.
            let outcome = self.renew_runtime_leases_for_probe(
                &request,
                renewed_head,
                live_receipt,
                crate::unix_ms(),
            )?;
            observe_runtime_lease_tick(&outcome);
        }
        // The renewed supervision head above proves lease continuity only. It
        // does not by itself prove an independent Watchdog response, so no
        // Material/Critical admission may be derived from it either; that path
        // re-verifies the live branch in `admit_material_authority_for_fence`.
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
                return Err(TransportError::SessionFenced.into());
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
                return Err(TransportError::SessionFenced.into());
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
                return Err(TransportError::SessionFenced.into());
            }
            // I1.11 step 11 is intentionally not latched by ProbeReady.
            // Only the typed per-tick progress path may set it after a fresh
            // observation explicitly reports Watchdog coverage; a signed lease
            // or a successful process handshake alone is not heartbeat proof.
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
        // I18.53 ACT-1 (#1918 A4): a granted activation issues its durable
        // runtime lease. The row is keyed by the stable activation operation
        // identity, fenced exactly like the activation itself, and expires
        // after the validity window; the retirement census reads it back
        // through the canonical ORS owner. No lock is held across the ORS
        // write: the service lock above is released before this statement.
        if let (KernelControlCommand::Activate(_), Some(receipt)) =
            (&request.command, &activation_receipt)
        {
            let fence = StateFence::new(request.candidate.kernel_epoch.clone(), request.generation);
            let expires_at_ms = crate::unix_ms()
                .checked_add(RUNTIME_LEASE_VALIDITY_MS)
                .ok_or(TransportError::SessionFenced)?;
            let lease = RuntimeLease {
                lease_id: receipt.operation_id.as_str().to_owned(),
                scope_ref: request.candidate.activation_id.as_str().to_owned(),
                authority_epoch: receipt.authority_epoch.clone(),
                state_fence: fence.clone(),
                state: LeaseState::Active,
                expires_at_ms,
            };
            self.generation_gateway
                .ors
                .record_runtime_lease_current(&lease)
                .map_err(|_| TransportError::SessionFenced)?;
            // I1.5 W4 (#1751): grant-time reconciliation beside issuance. The
            // tick clock terminalizes past-due rows for this fence, and the
            // grant supersedes stale same-scope identities, so a retried or
            // replaced activation operation never leaves two live rows for
            // one activation. Both move through the owner transition; the
            // census keeps classifying recorded rows and never rewrites them.
            let now_ms = crate::unix_ms();
            let outcome = RuntimeLeaseTickOutcome {
                expired: self.expire_past_due_runtime_leases(&fence, now_ms)?,
                superseded: self.supersede_stale_runtime_leases(
                    &fence,
                    request.candidate.activation_id.as_str(),
                    receipt.operation_id.as_str(),
                )?,
                ..Default::default()
            };
            observe_runtime_lease_tick(&outcome);
        }
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
                // I14.16 step 2/7: the candidate takes exclusive ownership of
                // its own installation/activation contour here, before it
                // adopts any lineage, so two Kernels can never both own the
                // same contour and Host has a real object to verify later.
                KernelControlCommand::Reconcile => {
                    // The exclusive owner object is a Windows named-object
                    // primitive; on other targets the contour has no
                    // cross-process owner object to take and this step is
                    // unreachable rather than simulated.
                    #[cfg(windows)]
                    self.acquire_kernel_owner(
                        &request.candidate.installation_id,
                        &request.candidate.activation_id,
                    )
                    .map_err(|_| TransportError::SessionFenced)?;
                    self.service
                        .lock()
                        .map_err(|_| TransportError::SessionFenced)?
                        .reconcile(request.candidate.clone())
                        .map_err(|_| TransportError::SessionFenced)?;
                }
                KernelControlCommand::BootstrapStore(_)
                | KernelControlCommand::Activate(_)
                | KernelControlCommand::ReconcileActivation(_)
                | KernelControlCommand::RebindStore(_)
                | KernelControlCommand::ReconcileRebindStore(_)
                | KernelControlCommand::ReportHostStartupEvidence(_)
                // I18.53 ACT-1 (#1918): the retirement census is a read-only
                // owner read, never a service state transition. Serving it
                // here keeps it out of the terminal-transition path whose
                // unauthenticated `transition` correctly refuses it.
                | KernelControlCommand::ReadRuntimeLeaseCensus(_) => {}
                // I1.5 W4 (#1751): administrative revocation is an explicit
                // owner write through the single-revocation helper below,
                // never a service state transition. Drain and stop never
                // revoke, so reconciliation duties cannot be abandoned
                // implicitly.
                KernelControlCommand::RevokeRuntimeLease(query) => {
                    self.revoke_runtime_lease(&query.state_fence, &query.lease_id)?;
                }
                command => {
                    self.apply_control_with_terminal(command.clone(), false)
                        .map_err(ControlRequestFailure::Transition)?;
                }
            }
        }
        #[cfg(windows)]
        if matches!(&request.command, KernelControlCommand::ProbeReady)
            && let Some(next) = prepared_bridge_profile
        {
            self.promote_agent_bridge_profile(next)?;
        }
        // I18.53 ACT-1 (#1918): serve the exact-fence retirement census from
        // the canonical ORS owner on its dedicated wire arm. The shared
        // envelope below already carries every other projection as `None` on
        // this arm, which is exactly the bare-census shape the response
        // validator and the Host retirement barrier require.
        let runtime_lease_census = match &request.command {
            KernelControlCommand::ReadRuntimeLeaseCensus(query) => Some(
                self.read_runtime_lease_census(&query.state_fence, &query.supervision_lease_id)
                    .map_err(|_| TransportError::SessionFenced)?,
            ),
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
            // #961 read-only retirement projections. The authenticated
            // boundary serves `ReadRuntimeLeaseCensus` from the canonical ORS
            // owner read above (#1918 ACT-1) and still refuses
            // `ReadIntroductionRows` with a typed `InvalidField`, because no
            // ORS owner read returns a complete introduction set. A response
            // therefore never carries an introduction set, and the refusal
            // keeps introductions out of readiness, activation, rebind and
            // census answers by construction. The census itself is served
            // only on its dedicated wire arm, never beside another receipt.
            runtime_lease_census,
            introduction_rows: None,
            error: None,
            payload_digest: String::new(),
        }
        .with_computed_digest()
        .map_err(|_| TransportError::SessionFenced.into())
    }

    /// Revokes one exact-fence `RuntimeLease` on explicit administrative
    /// command through the owner legality (I1.5 W4, #1751).
    ///
    /// Only the named non-terminal row bound to this exact fence moves, to
    /// `Revoked`, re-recorded through the canonical ORS owner; terminal rows
    /// are never rewritten and an unknown identity fails closed with the
    /// boundary's own `SessionFenced`. Drain and stop never revoke:
    /// revocation is explicit-command only, so reconciliation duties cannot
    /// be abandoned implicitly. The census keeps classifying recorded rows
    /// and never rewrites them.
    fn revoke_runtime_lease(
        &self,
        fence: &StateFence,
        lease_id: &str,
    ) -> Result<(), TransportError> {
        let rows = self
            .generation_gateway
            .ors
            .load_runtime_leases_by_state_fence(fence)
            .map_err(|_| TransportError::SessionFenced)?;
        let row = rows
            .iter()
            .find(|row| row.lease_id.as_str() == lease_id)
            .ok_or(TransportError::SessionFenced)?;
        if row.state_fence != *fence {
            return Err(TransportError::SessionFenced);
        }
        row.validate().map_err(|_| TransportError::SessionFenced)?;
        let revoked = row
            .transition_to(LeaseState::Revoked)
            .map_err(|_| TransportError::SessionFenced)?;
        self.generation_gateway
            .ors
            .record_runtime_lease_current(&revoked)
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(())
    }

    /// Revalidates the presented pre-suspend resume identities against live
    /// Kernel-observed state before any activation contour may reopen.
    ///
    /// I18.53 ACT-4 and I1.5: a resume never trusts a pre-suspend PID, pipe,
    /// authority epoch, `UserBroker` registration or lease identity. The six
    /// compared families are exactly
    /// [`eliot_runtime_contracts::revalidate_resume_identities`]'s contract
    /// set; this method only supplies the two snapshots from state the Kernel
    /// already observes and already compares, and refuses the request with the
    /// request boundary's own `TransportError::SessionFenced` when any family
    /// is stale, recording the typed coverage-gap families first.
    ///
    /// Every `current` value below is an existing Kernel observation, not a
    /// second source of truth: the live pipe name is `self.ipc.name()`, the
    /// live authority epoch is the front-door policy's own state fence, the
    /// live process identity is the handle-proven pipe peer, and the live
    /// lease identity is read back through the Kernel's own supervision-lease
    /// authority rather than from the request.
    ///
    /// The `Epoch` and `Broker` families are compared through
    /// [`Self::resume_epoch_is_presented_as_current`] and
    /// [`Self::resume_broker_is_presented_as_current`], which admit only the
    /// fenced-forward advances the epoch/generation fence below already admits
    /// and refuse everything else it refuses, so this gate is a strict subset of
    /// that fence. A `Reconcile` carrying a newer authority epoch or activation
    /// generation in the same lineage is a fenced-forward advance the fence goes
    /// on to synchronize, not a stale pre-suspend reuse; requiring exact
    /// equality here would make that advance unreachable without ever
    /// consulting the code that decides it.
    fn revalidate_activation_resume_identities(
        &self,
        request: &KernelControlRequest,
        peer: &PeerIdentity,
    ) -> Result<(), TransportError> {
        observe_control("kernel.control.resume_identity_checked", "attempt");
        let (current, presented, lease) = self.resume_identity_snapshots(request, peer)?;
        // A malformed snapshot anchors nothing: the contract documents that
        // the caller treats the shape error as fully stale, so the request is
        // fenced and the whole closed family set is the recorded gap.
        let Ok(revalidation) = revalidate_resume_identities(&current, &presented) else {
            // No verdict vector exists for a shape error, so the closed family
            // set supplies its own order here; this is the one place that does
            // not read the order from the contract.
            observe_resume_identity_gap(None, &ALL_RESUME_IDENTITY_FAMILIES);
            return Err(TransportError::SessionFenced);
        };
        // Three families have one single meaning in both directions, `Boot`,
        // `Process` and `Pipe`: equality against a live Kernel observation, so
        // the contract's own verdict decides them and is used unchanged. The
        // other three are re-decided by the rules the epoch/generation fence
        // already applies, or by the live-lease observation, so their raw
        // contract verdict is discarded rather than consulted. Consulting it
        // would reintroduce the defect this gate exists to avoid: the contract
        // compares `Epoch`, `Broker` and `Lease` by plain equality, so a
        // legitimate fenced-forward advance arrives here already marked stale.
        // For `Lease` the projection is deliberate rather than incidental:
        // `current.lease_ids` carries the `Live` set and nothing else, so the
        // contract's own verdict already agrees with the rule below and is not
        // read.
        let mut gap_families: Vec<eliot_runtime_contracts::ResumeIdentityFamily> = [
            eliot_runtime_contracts::ResumeIdentityFamily::Boot,
            eliot_runtime_contracts::ResumeIdentityFamily::Process,
            eliot_runtime_contracts::ResumeIdentityFamily::Pipe,
        ]
        .into_iter()
        .filter(|family| !resume_family_is_current(&revalidation, *family))
        .collect();
        let (epoch_current, broker_current, lease_current) =
            self.resume_forward_families(request, &presented, lease);
        if !epoch_current {
            gap_families.push(eliot_runtime_contracts::ResumeIdentityFamily::Epoch);
        }
        if !broker_current {
            gap_families.push(eliot_runtime_contracts::ResumeIdentityFamily::Broker);
        }
        if !lease_current {
            gap_families.push(eliot_runtime_contracts::ResumeIdentityFamily::Lease);
        }
        if gap_families.is_empty() {
            observe_control("kernel.control.resume_identity_checked", "success");
            return Ok(());
        }
        // The closed family vocabulary is the only payload. The gap is emitted
        // by walking the contract's own `verdicts` vector, which the contract
        // documents as "per-family verdicts in comparison order"
        // (`activation_lifecycle.rs:267`), so the recorded gap names each
        // family the contract compared, exactly once, in the contract's own
        // order — without a second copy of that order here that could drift
        // from the contract if the contract is reordered.
        observe_resume_identity_gap(Some(&revalidation.verdicts), &gap_families);
        Err(TransportError::SessionFenced)
    }

    /// Decides the three families whose verdict cannot be taken from the
    /// contract's plain equality, and says exactly why for each.
    ///
    /// `Epoch` defers to the fence's own `Reconcile` rule verbatim: the
    /// presented epoch is the current one for this request when it is the
    /// same authority as the live policy epoch, or when this is an explicit
    /// `Reconcile` whose presented epoch shares the live lineage and carries a
    /// strictly greater sequence. That second clause is the fenced-forward
    /// advance `apply_control_request_inner` goes on to admit by
    /// `synchronize_authority_epoch`; it is a new Host-approved epoch on a
    /// deliberate reconcile, not a silent inheritance of the pre-suspend one.
    /// Everything else — a different lineage, an older sequence, or a
    /// forward move on a command that is not `Reconcile` — stays stale, and
    /// the fence below still refuses it.
    ///
    /// `Epoch` and `Broker` are the forward-advance families and admit only what
    /// the epoch/generation fence below this gate admits, so this gate is a
    /// strict subset of that fence and never refuses a request the fence would
    /// go on to admit.
    ///
    /// `Lease` is decided from the observation the live ORS read actually
    /// made, not from the emptiness of the resulting set. A resolved head that
    /// is terminal, expired, or that fails its own validation is refused, and
    /// so is a head that did not resolve at all, so neither a revoked/expired
    /// presented lease nor an unprovable one is admitted. The rule is stated in
    /// full on [`ResumeLeaseObservation`] and in
    /// [`Self::resume_lease_is_presented_as_current`].
    fn resume_forward_families(
        &self,
        request: &KernelControlRequest,
        presented: &ResumeIdentitySnapshot,
        lease: ResumeLeaseObservation,
    ) -> (bool, bool, bool) {
        (
            self.resume_epoch_is_presented_as_current(request),
            self.resume_broker_is_presented_as_current(request),
            Self::resume_lease_is_presented_as_current(lease, presented),
        )
    }

    /// Applies the epoch/generation fence's own `Reconcile` advance rule to
    /// the ACT-4 `Epoch` family, so this gate and that fence cannot disagree
    /// about the same request.
    fn resume_epoch_is_presented_as_current(&self, request: &KernelControlRequest) -> bool {
        let Ok(policy) = self.front_door_policy.lock() else {
            // The fence below cannot read this state either, so no verdict is
            // claimed here; it refuses the request on its own lock failure.
            return false;
        };
        let live_epoch = &policy.module_generation.state_fence.authority_epoch;
        let presented_epoch = &request.candidate.kernel_epoch;
        presented_epoch.is_same_authority(live_epoch)
            || (matches!(&request.command, KernelControlCommand::Reconcile)
                && presented_epoch.lineage_id == live_epoch.lineage_id
                && presented_epoch.sequence.get() > live_epoch.sequence.get())
    }

    /// Applies the activation-generation advance rule to the ACT-4 `Broker`
    /// family.
    ///
    /// `KernelService::reconcile` is the only writer of the retained candidate
    /// contour (`lifecycle.rs:672`), and it is reached from exactly one place,
    /// `apply_control_request_inner`'s `KernelControlCommand::Reconcile` arm.
    /// Every other command reads the retained contour instead of replacing it,
    /// so a *different* `activation_generation` presented on any of them is a
    /// residue of a pre-suspend registration the Kernel has already moved past
    /// and stays stale. That is the whole rule; there is no further
    /// discriminator.
    ///
    /// The invariant this gate has to hold is that it never refuses a request
    /// the service would admit, and the shape above is what proves it. A
    /// forward generation advance on `Reconcile` needs no receipt test at all,
    /// because the gates below still apply: the candidate-binding checks at the
    /// top of `apply_control_request_inner` compare the presented binding
    /// against the *retained* one and refuse the mismatch, and
    /// `KernelService::reconcile` itself refuses an older or off-lineage
    /// `candidate.kernel_epoch` through `HostKernelCandidateBinding::validate`.
    /// The service additionally refuses from `Ready` and `Draining`
    /// (`lifecycle.rs:656-664`); this gate does not re-decide that, because a
    /// state-based refusal is exactly where the permanent lockout below would
    /// come from.
    ///
    /// The activation receipt cannot carry that information and is not consulted
    /// here. `rebind_store` moves `Ready -> Degraded` and *retains* the receipt
    /// (`lifecycle.rs:925`), and `Degraded -> Reconciling` is a legal
    /// `transition_to` edge, so a `Ready`-reached contour that was degraded by a
    /// Store rebind, then presented a correct forward-advance `Reconcile`,
    /// would be refused here while `reconcile` would have accepted it. Since the
    /// receipt is cleared only by `reconcile` — the very request being refused —
    /// such a refusal could never be retried successfully.
    fn resume_broker_is_presented_as_current(&self, request: &KernelControlRequest) -> bool {
        let Ok(service) = self.service.lock() else {
            // The service cannot be read here either, so the fences below own
            // this refusal rather than a verdict invented in this gate.
            return true;
        };
        let Some(live_candidate) = service.candidate_binding() else {
            // The very first activation of this Kernel: there is no retained
            // registration to inherit, so the contour this request presents is
            // the current one by construction and the family has nothing to
            // be stale against.
            return true;
        };
        let live_generation = &live_candidate.supervision_incarnation.activation_generation;
        let presented_generation = &request
            .candidate
            .supervision_incarnation
            .activation_generation;
        live_generation == presented_generation
            || (matches!(&request.command, KernelControlCommand::Reconcile)
                && presented_generation.lineage_id == live_generation.lineage_id
                && presented_generation.sequence > live_generation.sequence)
    }

    /// Applies the contract's own `Lease` rule to the ACT-4 `Lease` family,
    /// decided from the *observation* the live read actually made.
    ///
    /// The contract's rule is a subset test of the presented set against the
    /// live set, and it is kept verbatim. The only thing this adds is that the
    /// empty live set is not a single fact: it is one of the three outcomes
    /// [`Self::observe_current_resume_lease`] reports, and each is answered
    /// from which outcome was observed instead of from the emptiness of a set
    /// that is the same for all three.
    ///
    /// * [`ResumeLeaseObservation::Live`] — the presented lease is in the live
    ///   set, so the contract's subset rule admits it.
    /// * [`ResumeLeaseObservation::HeadPresentNotLive`] — the presented lease
    ///   *resolved* in the Kernel's own ORS and the resolved head is revoked,
    ///   expired, released, superseded or closed, or the head failed its own
    ///   validation. That is the "genuinely lost lease" ACT-4 exists to reject,
    ///   so the family is stale.
    /// * [`ResumeLeaseObservation::NoHead`] — nothing resolved, which is the
    ///   unreadable case; it fails closed on the rule
    ///   `idle_lease_census.rs:266-270` already documents.
    ///
    /// The previous shape of this gate read the empty live set as "this contour
    /// has no lease owner" and returned current, which is what admitted the
    /// revoked lease: on an integrated Windows composition an owner always
    /// exists, so that override made *every* non-live head current.
    fn resume_lease_is_presented_as_current(
        observation: ResumeLeaseObservation,
        presented: &ResumeIdentitySnapshot,
    ) -> bool {
        // A live set is authoritative, and the contract's own subset rule
        // decides it: a presented identity missing from the live set stays
        // stale. This re-reads nothing — the live set is the one the single
        // live read in `resume_identity_snapshots` resolved.
        match observation {
            ResumeLeaseObservation::Live { live_lease_ids } => presented
                .lease_ids
                .iter()
                .all(|lease| live_lease_ids.contains(lease)),
            // The two refusals share a verdict and are merged here on purpose:
            // they are different *observations* and the enum keeps them apart
            // so neither can be re-read as "no lease owner", but the rule this
            // gate enforces is the single one stated on
            // `ResumeLeaseObservation` — only a head proven live is current.
            // `HeadPresentNotLive` is the proven-gone lease ACT-4 must reject;
            // `NoHead` is the unreadable one, which fails closed for the reason
            // `idle_lease_census.rs:266-270` gives. An empty live set is
            // therefore never an admission, on any contour, including one whose
            // empty set is its only possible state.
            ResumeLeaseObservation::HeadPresentNotLive | ResumeLeaseObservation::NoHead => false,
        }
    }

    /// Projects live Kernel-observed state onto the ACT-4 `current` resume
    /// identity snapshot and the request's own authenticated content onto the
    /// `presented` one, and carries the live lease *observation* out beside
    /// them.
    ///
    /// The live epoch and the live candidate contour are read under one scope
    /// per shared lock, so those two cannot disagree with each other about the
    /// state the Kernel observed. The lease read that follows is a separate ORS
    /// read taken after those guards drop, and the family decisions in
    /// [`Self::resume_forward_families`] re-acquire `self.service` and
    /// `self.front_door_policy` again afterwards. What the pair therefore
    /// guarantees is the weaker, and only honest, statement: every value comes
    /// from a live Kernel-owned read taken while this request was being
    /// admitted, never from the request itself. A concurrent lifecycle command
    /// may advance the contour between those reads, which is why the decision
    /// helpers re-read the state they decide on rather than trusting a snapshot
    /// taken earlier.
    ///
    /// The live lease set projected into `current.lease_ids` is exactly
    /// [`ResumeLeaseObservation::Live`]'s set and nothing else: an observation
    /// that is not `Live` contributes an empty set there, so the contract's own
    /// `Lease` verdict agrees with this gate instead of contradicting it. The
    /// difference between the two refusals lives in `observation`, not in the
    /// set, which is why it is returned rather than thrown away.
    fn resume_identity_snapshots(
        &self,
        request: &KernelControlRequest,
        peer: &PeerIdentity,
    ) -> Result<
        (
            ResumeIdentitySnapshot,
            ResumeIdentitySnapshot,
            ResumeLeaseObservation,
        ),
        TransportError,
    > {
        let observed_peer = peer
            .process_binding()
            .ok_or(TransportError::PeerIdentityUnavailable)?;
        let live_pipe = self.ipc.name().to_owned();
        let (live_authority_epoch, live_candidate) = {
            let policy = self
                .front_door_policy
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let live_candidate = self
                .service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?
                .candidate_binding()
                .cloned();
            (
                policy.module_generation.state_fence.authority_epoch.clone(),
                live_candidate,
            )
        };
        // The Kernel's own live-retained candidate contour. When the previous
        // admitted request left one in place this is the fenced registration
        // the presented contour must still match; a first activation has
        // none, and the broker family is then compared against the
        // registration this very request establishes.
        let broker = match live_candidate {
            Some(live) => resume_broker_identity(peer, &live)?,
            None => resume_broker_identity(peer, &request.candidate)?,
        };
        let observation = self.observe_current_resume_lease(&request.candidate);
        let current = ResumeIdentitySnapshot {
            boot_id: current_resume_boot_identity()?,
            process: ResumeProcessIdentity {
                pid: observed_peer.process_id(),
                start_100ns: observed_peer.start_time_100ns(),
            },
            pipe_expectation: live_pipe,
            authority_epoch: live_authority_epoch,
            broker,
            lease_ids: match &observation {
                ResumeLeaseObservation::Live { live_lease_ids } => live_lease_ids.clone(),
                ResumeLeaseObservation::HeadPresentNotLive | ResumeLeaseObservation::NoHead => {
                    Vec::new()
                }
            },
        };
        let presented = presented_resume_identity_snapshot(request, peer, &current)?;
        Ok((current, presented, observation))
    }

    /// Reads the presented candidate's supervision-lease head through the
    /// Kernel's own lease authority and reports *which* of the three possible
    /// outcomes it observed, rather than an empty set for all three.
    ///
    /// The read is a live ORS lookup by the presented lease identity against the
    /// `SUPERVISION_LEASE_CURRENT` base table, which is only ever inserted, so a
    /// revoked, expired, released, superseded or closed lease still *resolves*
    /// here. Resolving is therefore not liveness, and the resolved head is
    /// filtered through the predicate this crate already uses to decide a
    /// supervision lease is live: `snapshot.validate().is_ok() && record.state ==
    /// LeaseState::Active && crate::unix_ms() < payload.expires_at_ms`, spelled by
    /// `SupervisionLeaseProjection::for_state` (`eliot-ors/src/model.rs:145`) and
    /// reused verbatim from `idle_lease_census::KernelIdleLeaseCensus::supervision_leg`
    /// — the I1.5 drain gate's own live-supervision test, in the same crate. A
    /// head that resolves and is not live is [`ResumeLeaseObservation::HeadPresentNotLive`];
    /// that is the genuinely-lost-lease case ACT-4 exists to reject, and it is
    /// refused rather than erased.
    ///
    /// A head that does not resolve at all is [`ResumeLeaseObservation::NoHead`],
    /// and it fails closed for the reason that precedent states verbatim: an
    /// absent head and a read that cannot be proven are "neither is evidence
    /// that the installation is idle, so both legs answer Unavailable and the
    /// drain gate stays closed" (`idle_lease_census.rs:266-270`). This gate is
    /// the same rule pointed the other way — an unprovable head is not evidence
    /// that the presented lease is current, so the family is stale.
    ///
    /// Without a composed supervision authority this contour has no lease
    /// surface at all and the read cannot be attempted, which is also
    /// [`ResumeLeaseObservation::NoHead`]: the unprovable case, and therefore a
    /// refusal, never an admission.
    #[cfg(windows)]
    fn observe_current_resume_lease(
        &self,
        candidate: &HostKernelCandidateBinding,
    ) -> ResumeLeaseObservation {
        let Some(authority) = self.supervision_lease_authority.as_ref() else {
            return ResumeLeaseObservation::NoHead;
        };
        // `Ok(None)` is an absent head and `Err(_)` an unproven read; the
        // census precedent treats both as unprovable, so both map to `NoHead`
        // and both are refused by the caller.
        let Ok(Some(snapshot)) =
            authority.current_snapshot(&candidate.supervision_incarnation.supervision_lease_id)
        else {
            return ResumeLeaseObservation::NoHead;
        };
        let live = snapshot.validate().is_ok()
            && snapshot.record.state == LeaseState::Active
            && crate::unix_ms() < snapshot.record.artifact.payload.expires_at_ms;
        if !live {
            return ResumeLeaseObservation::HeadPresentNotLive;
        }
        ResumeLeaseObservation::Live {
            live_lease_ids: vec![snapshot.record.lease_id.as_str().to_owned()],
        }
    }

    /// The non-Windows base has no supervision-lease surface, so the live read
    /// cannot be attempted and the observation is the unprovable `NoHead`.
    ///
    /// The rule requirement makes an exception for a contour that can never own
    /// a lease, and it is not claimed here: this arm refuses like every other
    /// `NoHead`. That costs nothing, because the non-Windows base never reaches
    /// this decision — `current_resume_boot_identity` is not `cfg`-gated and
    /// its `not(windows)` arm fences with `SessionFenced` first, and
    /// `main.rs` exits `AUTHENTICATED_CONTROL_UNSUPPORTED` before any front-door
    /// loop starts there. Refusing here is the same fail-closed reading the
    /// reachable Windows paths use, so there is one rule rather than a special
    /// case for an arm production cannot enter.
    #[cfg(not(windows))]
    const fn observe_current_resume_lease(
        &self,
        _candidate: &HostKernelCandidateBinding,
    ) -> ResumeLeaseObservation {
        ResumeLeaseObservation::NoHead
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
        let Ok(coordinator) = coordinator_for(&self.work_root) else {
            observe_control("kernel.control.drain_request_failed", "unavailable");
            return false;
        };
        if coordinator.request_shutdown().is_err() {
            observe_control("kernel.control.drain_request_failed", "unavailable");
            return false;
        }
        let view = self.activation_operational_view();
        observe_control(
            "kernel.control.drain_requested_observed",
            view.drain_disposition,
        );
        self.runtime.shutdown_handle().request()
    }
}

/// Bounded observation code for one wake-during-drain disposition.
const fn disposition_code(disposition: DrainWakeDisposition) -> &'static str {
    match disposition {
        DrainWakeDisposition::Proceed => "proceed",
        DrainWakeDisposition::CancelDrain => "cancel-drain",
        DrainWakeDisposition::QueueNextGeneration => "queue-next-generation",
        DrainWakeDisposition::RejectStale => "reject-stale",
    }
}

/// Stable domain for the ACT-4 boot identity derivation.
const RESUME_BOOT_ID_DOMAIN: &str = "eliot-kernel.resume-boot.v1";

/// Validity window in milliseconds for an activation-granted runtime lease
/// (I18.53 ACT-1, #1918 A4). The lease blocks the retirement census while
/// non-terminal and unexpired; afterwards the census observes it as expired
/// without rewriting it. Mirrors the supervision renewal policy's 60-second
/// validity in the same drain gate: one window for both halves of ACT-1, so
/// neither half can outlive the other's proof.
const RUNTIME_LEASE_VALIDITY_MS: u64 = 60_000;

/// Maximum age in milliseconds of probe-published evidence admitted as fresh
/// by the runtime-lease renewal tick (I1.5 W4, #1751). The tick builds its
/// evidence inline from the probe it is serving — the supervision head
/// renewed and the live receipt published earlier on that same probe — so
/// both timestamps fall inside one request handling; the window absorbs
/// clock-read skew between those two reads, never a stored observation.
/// Anything older fails the probe closed instead of renewing from stale
/// evidence.
#[cfg(windows)]
const RUNTIME_LEASE_EVIDENCE_FRESHNESS_MS: u64 = 5_000;

/// Counts of [`RuntimeLease`] rows one tick moved through the owner
/// [`RuntimeLease::transition_to`] legality and re-recorded through the
/// canonical ORS owner.
#[derive(Debug, Default)]
struct RuntimeLeaseTickOutcome {
    renewed: usize,
    expired: usize,
    superseded: usize,
}

/// Observes one runtime-lease tick that moved at least one row.
///
/// F-LOG-KERNEL-4 (#903): fixed `kernel.control.*` event name plus bounded
/// counts only; no lease identity, scope, fence, or owner error string ever
/// leaves this boundary (I15.4, I07.20). Ticks that move nothing stay
/// unlogged, exactly like the supervision leg's routine not-due ticks.
fn observe_runtime_lease_tick(outcome: &RuntimeLeaseTickOutcome) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    if outcome.renewed == 0 && outcome.expired == 0 && outcome.superseded == 0 {
        return;
    }
    let event_bound = bound_field("kernel.control.runtime_lease_tick");
    let renewed_bound = bound_field(&outcome.renewed.to_string());
    let expired_bound = bound_field(&outcome.expired.to_string());
    let superseded_bound = bound_field(&outcome.superseded.to_string());
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        renewed = renewed_bound.text(),
        expired = expired_bound.text(),
        superseded = superseded_bound.text(),
        "control plane runtime lease tick"
    );
}

/// Terminal [`LeaseState`] set for the runtime-lease tick. Mirrors the
/// retirement gate the Host consumes
/// (`RuntimeLeaseCensus::is_fully_retired`) and the `idle_lease_census`
/// runtime leg: only a terminal row stops blocking the drain.
fn runtime_lease_is_terminal(state: LeaseState) -> bool {
    matches!(
        state,
        LeaseState::Released
            | LeaseState::Expired
            | LeaseState::Revoked
            | LeaseState::Superseded
            | LeaseState::Closed
    )
}

impl KernelComposition {
    /// Loads the exact-fence [`RuntimeLease`] current set and re-validates
    /// every row before the tick trusts it.
    ///
    /// The loader already selects by exact fence equality and key-checks each
    /// row against its own lease identity; the tick re-checks the fence and
    /// runs the owner [`RuntimeLease::validate`] anyway, so a corrupt row
    /// fails the request closed instead of being renewed, expired, or
    /// silently skipped.
    fn load_validated_runtime_leases(
        &self,
        fence: &StateFence,
    ) -> Result<Vec<RuntimeLease>, TransportError> {
        let rows = self
            .generation_gateway
            .ors
            .load_runtime_leases_by_state_fence(fence)
            .map_err(|_| TransportError::SessionFenced)?;
        for row in &rows {
            if row.state_fence != *fence {
                return Err(TransportError::SessionFenced);
            }
            row.validate().map_err(|_| TransportError::SessionFenced)?;
        }
        Ok(rows)
    }

    /// Terminalizes past-due non-terminal rows through the owner
    /// [`RuntimeLease::transition_to`] legality and re-records each terminal
    /// revision through the canonical ORS owner (I1.5 W4, #1751).
    ///
    /// The tick clock is the only evidence expiry needs — "if renewal cannot
    /// be proved, coverage ends at expiry and is reported honestly" — so no
    /// observation is consumed here; renewal evidence enters only through
    /// [`Self::renew_runtime_leases_for_probe`]. A past-due row in any
    /// non-terminal state moves to `Expired`; terminal rows are never
    /// rewritten. The census keeps classifying recorded `expires_at_ms`
    /// values and never rewrites them itself.
    fn expire_past_due_runtime_leases(
        &self,
        fence: &StateFence,
        now_ms: u64,
    ) -> Result<usize, TransportError> {
        let rows = self.load_validated_runtime_leases(fence)?;
        let mut expired = 0;
        for row in &rows {
            if runtime_lease_is_terminal(row.state) || now_ms < row.expires_at_ms {
                continue;
            }
            let terminal = row
                .transition_to(LeaseState::Expired)
                .map_err(|_| TransportError::SessionFenced)?;
            self.generation_gateway
                .ors
                .record_runtime_lease_current(&terminal)
                .map_err(|_| TransportError::SessionFenced)?;
            expired += 1;
        }
        Ok(expired)
    }

    /// Supersedes stale same-scope identities after a new grant through the
    /// owner [`RuntimeLease::transition_to`] legality (I1.5 W4, #1751).
    ///
    /// Only non-terminal rows bound to this exact fence and scope but
    /// carrying another lease identity move, to `Superseded`: a retried or
    /// replaced activation operation must never leave two live rows for one
    /// activation, and old and new authority never overlap merely to make
    /// wake-up appear fast. Rows held by another activation are another
    /// obligation and are never touched; only `Active` rows are superseded —
    /// no writer records any other live state, and anything else converges
    /// through the expiry pass instead of a contorted transition.
    fn supersede_stale_runtime_leases(
        &self,
        fence: &StateFence,
        scope_ref: &str,
        current_lease_id: &str,
    ) -> Result<usize, TransportError> {
        let rows = self.load_validated_runtime_leases(fence)?;
        let mut superseded = 0;
        for row in &rows {
            if row.lease_id.as_str() == current_lease_id
                || row.scope_ref.as_str() != scope_ref
                || row.state != LeaseState::Active
            {
                continue;
            }
            let terminal = row
                .transition_to(LeaseState::Superseded)
                .map_err(|_| TransportError::SessionFenced)?;
            self.generation_gateway
                .ors
                .record_runtime_lease_current(&terminal)
                .map_err(|_| TransportError::SessionFenced)?;
            superseded += 1;
        }
        Ok(superseded)
    }

    /// Renews the live rows this probe holds from this probe's fresh
    /// observable evidence, expiring what is past due (I1.5 W4, #1751).
    ///
    /// The evidence is the renewed supervision head plus the live receipt
    /// published earlier on this same probe: the head must still be `Active`
    /// and fenced exactly like this candidate, and the receipt must name
    /// this installation with a publication time inside
    /// [`RUNTIME_LEASE_EVIDENCE_FRESHNESS_MS`] of the tick clock. Anything
    /// else fails the probe closed instead of renewing from stale evidence;
    /// process survival alone never renews.
    ///
    /// Renewal is a new revision of the same lease identity through the owner
    /// legality — `Active` passes through `Expiring` back to `Active`,
    /// `Expiring` returns to `Active` directly — with a fresh
    /// [`RUNTIME_LEASE_VALIDITY_MS`] window, re-validated and re-recorded
    /// through the canonical ORS owner. Only live rows held by this
    /// activation (`scope_ref` equal to the candidate activation) renew;
    /// another activation's live rows are never touched, and live rows in no
    /// renewable state fail closed rather than being skipped silently.
    #[cfg(windows)]
    fn renew_runtime_leases_for_probe(
        &self,
        request: &KernelControlRequest,
        renewed: &SupervisionLeaseSnapshot,
        live_receipt: &EliotdLiveReceipt,
        now_ms: u64,
    ) -> Result<RuntimeLeaseTickOutcome, TransportError> {
        let fence = StateFence::new(request.candidate.kernel_epoch.clone(), request.generation);
        if renewed.record.state != LeaseState::Active || renewed.record.binding.state_fence != fence
        {
            return Err(TransportError::SessionFenced);
        }
        if live_receipt.installation_id.as_str() != request.candidate.installation_id.as_str()
            || live_receipt.published_at_unix_ms > now_ms
            || now_ms.saturating_sub(live_receipt.published_at_unix_ms)
                > RUNTIME_LEASE_EVIDENCE_FRESHNESS_MS
        {
            return Err(TransportError::SessionFenced);
        }
        let rows = self.load_validated_runtime_leases(&fence)?;
        let activation_id = request.candidate.activation_id.as_str();
        let mut outcome = RuntimeLeaseTickOutcome::default();
        for row in &rows {
            if runtime_lease_is_terminal(row.state) {
                continue;
            }
            if now_ms >= row.expires_at_ms {
                let terminal = row
                    .transition_to(LeaseState::Expired)
                    .map_err(|_| TransportError::SessionFenced)?;
                self.generation_gateway
                    .ors
                    .record_runtime_lease_current(&terminal)
                    .map_err(|_| TransportError::SessionFenced)?;
                outcome.expired += 1;
                continue;
            }
            if row.scope_ref.as_str() != activation_id {
                continue;
            }
            let active = match row.state {
                LeaseState::Active => row
                    .transition_to(LeaseState::Expiring)
                    .and_then(|next| next.transition_to(LeaseState::Active)),
                LeaseState::Expiring => row.transition_to(LeaseState::Active),
                _ => return Err(TransportError::SessionFenced),
            }
            .map_err(|_| TransportError::SessionFenced)?;
            let mut renewed_row = active;
            renewed_row.expires_at_ms = now_ms
                .checked_add(RUNTIME_LEASE_VALIDITY_MS)
                .ok_or(TransportError::SessionFenced)?;
            renewed_row
                .validate()
                .map_err(|_| TransportError::SessionFenced)?;
            self.generation_gateway
                .ors
                .record_runtime_lease_current(&renewed_row)
                .map_err(|_| TransportError::SessionFenced)?;
            outcome.renewed += 1;
        }
        Ok(outcome)
    }
}

/// What the Kernel's own supervision-lease authority actually observed for the
/// lease identity a resume presents.
///
/// An earlier shape of this gate returned only the live set, so an empty set
/// meant "no lease owner", "no head established" and "the head is revoked" at
/// once, and the caller read that single empty as "nothing to reject". This
/// type keeps the three apart at the point of observation, where they are still
/// distinguishable, and the `Lease` verdict is taken from which one was
/// observed. It is an observation record, not a second source of truth: it is
/// produced by the one live ORS read in
/// `KernelComposition::observe_current_resume_lease` and decided once by
/// `KernelComposition::resume_lease_is_presented_as_current`.
///
/// Only `Live` is ever admitted. That is deliberately stricter than the
/// contract's own subset rule, which would admit an empty presented set against
/// an empty live one, and it is the same direction as the in-crate precedent
/// `idle_lease_census::KernelIdleLeaseCensus::supervision_leg` follows: a read
/// that cannot be proven is "neither … evidence that the installation is idle,
/// so both legs answer Unavailable and the drain gate stays closed". A resume
/// that cannot prove its presented lease is live is not thereby proven current.
#[derive(Debug)]
enum ResumeLeaseObservation {
    /// The head resolved and is active and unexpired. `live_lease_ids` is the
    /// live set the contract's subset rule is applied to.
    Live {
        /// The lease identities this contour can prove are live right now.
        live_lease_ids: Vec<String>,
    },
    /// The head resolved, and it says the lease is gone: revoked, expired,
    /// released, superseded or closed, or the head failed its own validation.
    /// The lease genuinely existed and is no longer usable, which is exactly
    /// the "genuinely lost lease" ACT-4 requires this gate to reject.
    HeadPresentNotLive,
    /// Nothing resolved. Either this contour has no supervision-lease surface
    /// at all — the non-Windows base, and any composition without a composed
    /// authority — or the ORS read returned no head or errored. This is the
    /// unprovable case and is refused; it is *not* evidence that the presented
    /// lease is still current, and it is not evidence that it was lost either.
    ///
    /// "Never established" and "established and since lost" are genuinely
    /// indistinguishable here: a `SUPERVISION_LEASE_CURRENT` head that was
    /// never written and one that was written and then lost both answer
    /// `Ok(None)`. That is precisely why this case fails closed instead of
    /// being split by a guess, and it is why the previous "a contour that can
    /// own no lease, so an empty set is harmless" override had to go: on a
    /// contour that *can* own a lease, that override admitted the identical
    /// revoked lease. The requirement permits `NoHead` to stay current on a
    /// contour that can never own a lease, and that exception is deliberately
    /// not taken — see `Self::observe_current_resume_lease`'s `not(windows)`
    /// arm for why it is unreachable and costs nothing.
    NoHead,
}

/// The complete closed ACT-4 family set, used to record a coverage gap when
/// a snapshot is malformed and therefore anchors nothing at all.
///
/// The contract documents that a malformed snapshot makes the caller treat
/// the comparison as fully stale, so this is the exact family list such a
/// refusal reports; it is not an independent enumeration.
const ALL_RESUME_IDENTITY_FAMILIES: [eliot_runtime_contracts::ResumeIdentityFamily; 6] = [
    eliot_runtime_contracts::ResumeIdentityFamily::Boot,
    eliot_runtime_contracts::ResumeIdentityFamily::Process,
    eliot_runtime_contracts::ResumeIdentityFamily::Pipe,
    eliot_runtime_contracts::ResumeIdentityFamily::Epoch,
    eliot_runtime_contracts::ResumeIdentityFamily::Broker,
    eliot_runtime_contracts::ResumeIdentityFamily::Lease,
];

/// Returns the ACT-4 boot identity of the running Kernel process.
///
/// The boot identity is derived from the Kernel's own process identity (PID
/// plus the handle-proven OS start instant), so it is stable for exactly one
/// Kernel incarnation: a Kernel replaced across a suspend/hibernate/logoff
/// resume observes a different process and can never present the pre-suspend
/// boot. The derivation is one-way and carries no image path, so the recorded
/// value reveals no identity material. `std::process::id()` and the process
/// start instant are the two live observations; nothing here is a constant
/// contour invented by the caller.
///
/// This helper is deliberately not `cfg`-gated. `observe_named_pipe_peer_process`
/// has a `not(windows)` arm that returns `Unavailable`
/// (`eliot-platform-windows/src/named_pipe_process_admission.rs:555`), so on
/// the non-Windows base the boot observation is unprovable and this fences with
/// `SessionFenced`. That path is unreachable in production — `main.rs` exits
/// `AUTHENTICATED_CONTROL_UNSUPPORTED` before any front-door loop starts on
/// non-Windows — and failing closed there is the correct answer for a resume
/// that cannot prove its own boot, so the fence is kept rather than special-cased
/// away.
fn current_resume_boot_identity() -> Result<String, TransportError> {
    let kernel_process = observe_named_pipe_peer_process(std::process::id())
        .map_err(|_| TransportError::SessionFenced)?;
    Ok(sha256_hex(
        format!(
            "{RESUME_BOOT_ID_DOMAIN}:{}:{}",
            kernel_process.process_id(),
            kernel_process.start_time_100ns()
        )
        .as_bytes(),
    ))
}

/// Projects the live `UserBroker` registration contour onto the ACT-4 broker
/// family.
///
/// `windows_sid` and `interactive_session_id` are the impersonation-proven
/// peer values the Kernel already authenticates; the registration's boot
/// session is that same proven logon session. `user_broker_epoch` is the
/// journal-owned activation-generation sequence of the contour in question —
/// the exact epoch a new `UserBrokerEpoch` fences (I1.4). Nothing here is read
/// from the incoming request, so a `current` built from the Kernel's
/// live-retained candidate contour is a genuine observation.
fn resume_broker_identity(
    peer: &PeerIdentity,
    candidate: &HostKernelCandidateBinding,
) -> Result<ResumeBrokerIdentity, TransportError> {
    let (windows_sid, interactive_session_id) = match peer {
        PeerIdentity::Authenticated {
            user_identity,
            session_identity,
            ..
        } => (user_identity.clone(), session_identity.clone()),
        PeerIdentity::Unavailable { .. } => return Err(TransportError::PeerIdentityUnavailable),
    };
    Ok(ResumeBrokerIdentity {
        windows_sid,
        interactive_session_id: interactive_session_id.clone(),
        boot_session_id: interactive_session_id,
        user_broker_epoch: candidate
            .supervision_incarnation
            .activation_generation
            .sequence,
    })
}

/// Projects the identities the reconnecting resume presents onto the ACT-4
/// comparison snapshot.
///
/// Every value is the request's own authenticated content: the presented
/// pipe expectation, the presented Kernel authority epoch, the presented
/// Host process identity, and the presented journal-owned generation the
/// `UserBroker` registration is fenced by. The presented lease set is the
/// exact presented supervision-lease identity.
///
/// The presented boot is the boot this very request arrived on. The control
/// wire deliberately carries no pre-suspend boot value: a resume therefore
/// has no way to present a stale boot, and the only boot that can reach this
/// boundary is the current one. The family is still compared rather than
/// assumed, so a future carrier that does present a boot value is fenced by
/// the same contract instead of silently admitted.
fn presented_resume_identity_snapshot(
    request: &KernelControlRequest,
    peer: &PeerIdentity,
    current: &ResumeIdentitySnapshot,
) -> Result<ResumeIdentitySnapshot, TransportError> {
    Ok(ResumeIdentitySnapshot {
        boot_id: current.boot_id.clone(),
        process: ResumeProcessIdentity {
            pid: request.candidate.host_process.process_id,
            start_100ns: request.candidate.host_process.start_time_100ns,
        },
        pipe_expectation: request.candidate.pipe_identity.as_str().to_owned(),
        authority_epoch: request.candidate.kernel_epoch.clone(),
        broker: resume_broker_identity(peer, &request.candidate)?,
        lease_ids: vec![
            request
                .candidate
                .supervision_incarnation
                .supervision_lease_id
                .clone(),
        ],
    })
}

/// Whether the contract itself compared one family as current.
///
/// The closed family vocabulary is the whole query surface: a family the
/// contract did not compare cannot be reported as current, and a family it did
/// compare carries that verdict verbatim. This reads the contract's own
/// per-family verdicts rather than re-deriving them, so the recorded gap can
/// never disagree with the comparison that produced it.
fn resume_family_is_current(
    revalidation: &eliot_runtime_contracts::ResumeRevalidation,
    family: eliot_runtime_contracts::ResumeIdentityFamily,
) -> bool {
    revalidation
        .verdicts
        .iter()
        .find(|(compared, _)| *compared == family)
        .is_some_and(|(_, verdict)| {
            *verdict == eliot_runtime_contracts::ResumeIdentityVerdict::Current
        })
}

/// Records the ACT-4 resume-identity coverage gap through the established
/// Kernel control observation vocabulary (F-LOG-KERNEL-4, #903).
///
/// The recorded material is exactly the typed families this gate found stale,
/// spelled by the family's own frozen `ResumeIdentityFamily::as_str` and
/// emitted through the same bounded-field helper every other control
/// observation uses. No identity, digest, PID, pipe name, SID, or owner error
/// string reaches the sink (I15.4, I07.20): the closed family vocabulary is
/// the whole payload.
///
/// `stale` is a set, and the emission order is the contract's own comparison
/// order — the `verdicts` vector, which the contract documents as "per-family
/// verdicts in comparison order". The order is therefore read from the contract
/// rather than restated here, so a future reordering of the contract cannot
/// silently desynchronise a second hand-maintained copy of it. `verdicts` is
/// `None` only on the shape-error path, where no comparison ran and the caller
/// supplies the whole closed set already in the contract's order.
fn observe_resume_identity_gap(
    verdicts: Option<
        &[(
            eliot_runtime_contracts::ResumeIdentityFamily,
            eliot_runtime_contracts::ResumeIdentityVerdict,
        )],
    >,
    stale: &[eliot_runtime_contracts::ResumeIdentityFamily],
) {
    let ordered = match verdicts {
        Some(verdicts) => verdicts
            .iter()
            .map(|(family, _)| *family)
            .filter(|family| stale.contains(family))
            .collect::<Vec<_>>(),
        None => stale.to_vec(),
    };
    for family in ordered {
        observe_control(
            "kernel.control.resume_identity_gap_observed",
            family.as_str(),
        );
    }
}

/// Test-only legacy shape check retained for existing unit fixtures. It is
/// not a production Watchdog coverage signal and is never called by the
/// control plane.
#[cfg(test)]
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
