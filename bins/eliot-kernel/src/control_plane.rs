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
use tracing::Instrument;

/// F-LOG-KERNEL-4 (#903): control-plane boundary observations.
///
/// Observation only, via #895's facade: fixed `kernel.control.*` event names
/// plus a bounded stable outcome. Never carries request payloads, digests,
/// peer identities, pipe names, or owner error strings (I15.4, I07.20).
fn observe_control(event: &'static str, outcome: &'static str) {
    observe_control_in_context(event, outcome, &tracing::Span::current());
}

fn observe_control_in_context(event: &'static str, outcome: &'static str, context: &tracing::Span) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        parent: context,
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
    /// A nested operation already owns the failed operation terminal.
    TerminalOwned(TransportError),
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
        let context = super::kernel_diagnostics::operation_context(None, None, None, None);
        self.apply_control_with_terminal(command, true, &context)
    }

    fn apply_control_with_terminal(
        &self,
        command: KernelControlCommand,
        emit_terminal: bool,
        context: &tracing::Span,
    ) -> Result<KernelServiceState, KernelServiceError> {
        observe_control_in_context("kernel.control.transition_requested", "attempt", context);
        match self.apply_control_inner(command) {
            Ok(state) => {
                observe_control_in_context(
                    "kernel.control.transition_committed",
                    "success",
                    context,
                );
                Ok(state)
            }
            Err(error) => {
                observe_control_in_context("kernel.control.transition_failed", "rejected", context);
                if emit_terminal {
                    super::kernel_diagnostics::observe_terminal_error_in_context(
                        control_transition_terminal_code(&error),
                        context,
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
        let validated = request.validate().is_ok();
        let generation = validated.then(|| request.generation.value().to_string());
        let epoch = validated
            .then(|| StateFence::canonical_epoch_digest(&request.candidate.kernel_epoch).ok())
            .flatten();
        let context = super::kernel_diagnostics::operation_context(
            validated.then_some(request.message_id.as_str()),
            generation.as_deref(),
            None,
            epoch.as_ref().map(eliot_contracts::LowercaseSha256::as_str),
        );
        if validated {
            let request_id = super::kernel_diagnostics::bound_field(request.message_id.as_str());
            context.record("request_id", request_id.text());
            context.record(
                "request_id_redaction",
                request_id.redaction_status().unwrap_or("none"),
            );
        }
        observe_control_in_context("kernel.control.request_received", "attempt", &context);
        match Box::pin(self.apply_control_request_inner(request, peer, expected_sequence, &context))
            .instrument(context.clone())
            .await
        {
            Ok(response) => {
                observe_control_in_context("kernel.control.request_admitted", "success", &context);
                Ok(response)
            }
            Err(error) => {
                observe_control_in_context("kernel.control.request_denied", "rejected", &context);
                let (terminal_code, transport_error, emit_terminal) = match error {
                    ControlRequestFailure::Transport(error) => {
                        (control_request_terminal_code(&error), error, true)
                    }
                    ControlRequestFailure::Transition(error) => (
                        control_transition_terminal_code(&error),
                        TransportError::SessionFenced,
                        true,
                    ),
                    ControlRequestFailure::TerminalOwned(error) => {
                        (control_request_terminal_code(&error), error, false)
                    }
                };
                if emit_terminal {
                    super::kernel_diagnostics::observe_terminal_error_in_context(
                        terminal_code,
                        &context,
                    );
                }
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
        context: &tracing::Span,
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
            evidence
                .validate(&request.candidate, request.generation)
                .map_err(|_| TransportError::SessionFenced)?;
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
                self.admit_host_observed_watchdog_branch(
                    &evidence.startup_evidence,
                    &request.candidate,
                    &target,
                )
                .map_err(|_| TransportError::SessionFenced)?;
            }
            // Typed provenance rows are validated as transport input above.
            // They are not an I1.11 probe and have no Kernel candidate
            // admission/readback owner yet, so this path does not turn them
            // into startup or generation authority.
            self.consume_host_startup_evidence(&evidence.startup_evidence)?;
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
        // I14.23 wake/attach race: an activation-family attach arriving before
        // the `DrainCommit` linearization point cancels the drain and
        // proceeds; after linearization it cannot reuse the drained generation
        // (the service independently fences `Activate` from `Draining`) and
        // must re-establish a fresh generation through the reconcile path.
        //
        // `ReconcileActivation` is in this family, and that is the load-bearing
        // part. I1.5 names the reconcile path as where a post-linearization
        // attach *receives* a fresh generation, and `KernelService::
        // reconcile_activation` answers it by handing back the very
        // `KernelActivationReceipt` `activate_permit` minted before the drain —
        // the pre-drain lease. An attach that skipped this gate and went
        // straight to the reconcile therefore left with drained authority
        // intact, which is precisely "rescuing shutdown by reviving an old
        // lease" that I14.23 forbids. It also read as the *safe* retry: a caller
        // whose `Activate` answer was lost during the drain would retry with
        // reconcile, so the one command most likely to be issued mid-drain was
        // the one command that skipped the race classification entirely.
        if matches!(
            &request.command,
            KernelControlCommand::Activate(_) | KernelControlCommand::ReconcileActivation(_)
        ) {
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
            let mut terminal_owned = false;
            Some(
                self.renew_daemon_supervision_for_probe_in_context(
                    &request,
                    context,
                    &mut terminal_owned,
                )
                .map_err(|_| {
                    if terminal_owned {
                        ControlRequestFailure::TerminalOwned(TransportError::SessionFenced)
                    } else {
                        ControlRequestFailure::Transport(TransportError::SessionFenced)
                    }
                })?,
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
                let mut terminal_owned = false;
                Some(
                    self.self_authored_ready_receipt_in_context(
                        &request,
                        peer,
                        context,
                        &mut terminal_owned,
                    )
                    .await
                    .map_err(|_| {
                        if terminal_owned {
                            ControlRequestFailure::TerminalOwned(TransportError::SessionFenced)
                        } else {
                            ControlRequestFailure::Transport(TransportError::SessionFenced)
                        }
                    })?,
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
            self.verify_published_eliotd_live_receipt(expected_live_receipt, context)
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
        // runtime lease. The row is keyed by the generation-bound identity
        // [`runtime_lease_id_for_candidate`] derives from the validated
        // candidate — the same `runtime-lease:<activation>:<lineage>:<seq>`
        // spelling the Host holds and names
        // (`bins/eliot-host/src/activation_lifecycle.rs::runtime_lease_id_for`),
        // so issuance, renewal, revocation, and the census resolve one
        // identity through the ORS owner. The row is fenced exactly like the
        // activation itself, and expires after the validity window; the
        // retirement census reads it back through the canonical ORS owner. No
        // lock is held across the ORS write: the service lock above is
        // released before this statement.
        if let (KernelControlCommand::Activate(_), Some(receipt)) =
            (&request.command, &activation_receipt)
        {
            let fence = StateFence::new(request.candidate.kernel_epoch.clone(), request.generation);
            let lease_id = runtime_lease_id_for_candidate(&request.candidate)?;
            let expires_at_ms = crate::unix_ms()
                .checked_add(RUNTIME_LEASE_VALIDITY_MS)
                .ok_or(TransportError::SessionFenced)?;
            let lease = RuntimeLease {
                lease_id: lease_id.clone(),
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
                    lease_id.as_str(),
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
            // Issue #1884 (I1.9, AUD3): the operator activation is a PRODUCTION
            // launch, so it reaches the process authority under the immutable
            // `KernelExecutionManifest` recorded for the exact generation this
            // activation names, through the same sealed launch gate the bounded
            // recovery uses. It is not a fallback around that gate: a generation
            // whose manifest is absent, receipt-less, stale, incompatible,
            // revoked or identity-mismatched launches nothing here, and I1.9
            // keeps that a visible degradation and escalation instead of an
            // improvised start.
            //
            // This module stays wiring. The manifest read, the refusal
            // classification, the durable escalation into the ORS owner's own
            // reconciliation and lifecycle rows, and the sealed binding all
            // belong to `KernelComposition::launch_eliotd_for_activation_under_manifest`
            // in `daemon_runtime.rs`; this call site keeps the same typed
            // refusal it already owned, and this module no longer names the
            // process primitive `KernelComposition::launch_eliotd_in_context`
            // at all. Nothing here admits on "a manifest exists" alone: the
            // launch is admitted only by the sealed binding the ORS verifier
            // issued for this exact module and generation.
            let launched = self
                .launch_eliotd_for_activation_under_manifest(context)
                .await
                .map_err(|_| ControlRequestFailure::TerminalOwned(TransportError::SessionFenced))?;
            self.await_daemon_ready(&launched, self.ipc_limits().operation_timeout, context)
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
                    self.apply_control_with_terminal(command.clone(), false, context)
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

/// Durable identity prefix for one activation-generation runtime lease.
///
/// Byte-identical to the Host projection
/// (`bins/eliot-host/src/activation_lifecycle.rs::RUNTIME_LEASE_ID_PREFIX`):
/// one spelling owned by the two lanes' shared journal content, never a
/// second scheme beside the ORS family.
const RUNTIME_LEASE_ID_PREFIX: &str = "runtime-lease";

/// Derives the generation-bound [`RuntimeLease`] identity for the validated
/// candidate contour (I1.5 W4, #1751).
///
/// The identity is built from the candidate's activation identity and the
/// journal-read activation-generation lineage/sequence the Host bound into
/// `supervision_incarnation` — the same content Host's
/// (`bins/eliot-host/src/activation_lifecycle.rs::runtime_lease_id_for`)
/// formats from its journal record, so the issued ORS row, the Host-held
/// reference, the renewal tick, the supersede comparison, the census rows,
/// and the explicit `RevokeRuntimeLease` name all resolve to one identity
/// through the ORS owner. The incarnation is re-validated through its
/// existing owner `validate()` (which binds the generation content to the
/// derived supervision identity), and the contour activation identity must
/// agree with the incarnation's journal-read one; anything else fails the
/// request closed instead of issuing under a second scheme.
fn runtime_lease_id_for_candidate(
    candidate: &HostKernelCandidateBinding,
) -> Result<String, TransportError> {
    let incarnation = &candidate.supervision_incarnation;
    incarnation
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    if incarnation.activation_id != candidate.activation_id.as_str() {
        return Err(TransportError::SessionFenced);
    }
    Ok(format!(
        "{RUNTIME_LEASE_ID_PREFIX}:{}:{}:{}",
        candidate.activation_id.as_str(),
        incarnation.activation_generation.lineage_id,
        incarnation.activation_generation.sequence,
    ))
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

    /// Terminalizes past-due non-terminal rows through reconciliation and
    /// the disposition-named close, re-recording each terminal revision
    /// through the canonical ORS owner (I1.5 W4, #1751).
    ///
    /// The tick clock is the only evidence expiry needs — "if renewal cannot
    /// be proved, coverage ends at expiry and is reported honestly" — so no
    /// observation is consumed here; renewal evidence enters only through
    /// [`Self::renew_runtime_leases_for_probe`]. A past-due row in any
    /// non-terminal state reaches `Expired` through
    /// [`Self::terminalize_past_due_runtime_lease`]: an `Active` row enters
    /// `Reconciling` with `Expired` named from its own past-due condition and
    /// closes through that named cleanup in the same tick, so orphaned leases
    /// expire and enter reconciliation without ever blocking the next census.
    /// Terminal rows are never rewritten. The census keeps classifying
    /// recorded `expires_at_ms` values and never rewrites them itself.
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
            self.terminalize_past_due_runtime_lease(fence, row)?;
            expired += 1;
        }
        Ok(expired)
    }

    /// Terminalizes one past-due non-terminal row through the owner
    /// [`RuntimeLease::transition_to`] legality and the canonical ORS owner
    /// (I1.5 W4, #1751).
    ///
    /// An `Active` row enters `Reconciling` through the ORS entry driver with
    /// `Expired` named from its own past-due condition, then closes through
    /// the ORS exit driver with that same named cleanup; a `Reconciling` row
    /// left by a crashed tick closes through the exit driver directly. Rows
    /// in any other live state move straight to `Expired` — the owner admits
    /// no other `Reconciling` entry — and terminal rows never reach here. A
    /// failure fences the request instead of skipping the row silently.
    fn terminalize_past_due_runtime_lease(
        &self,
        fence: &StateFence,
        row: &RuntimeLease,
    ) -> Result<(), TransportError> {
        let ors = &self.generation_gateway.ors;
        if row.state == LeaseState::Active {
            ors.reconcile_runtime_lease_for_terminal_disposition(
                fence,
                row.lease_id.as_str(),
                LeaseState::Expired,
            )
            .map_err(|_| TransportError::SessionFenced)?;
        }
        if row.state == LeaseState::Active || row.state == LeaseState::Reconciling {
            ors.close_reconciled_runtime_lease_for_disposition(
                fence,
                row.lease_id.as_str(),
                LeaseState::Expired,
            )
            .map_err(|_| TransportError::SessionFenced)?;
            return Ok(());
        }
        let terminal = row
            .transition_to(LeaseState::Expired)
            .map_err(|_| TransportError::SessionFenced)?;
        ors.record_runtime_lease_current(&terminal)
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(())
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
                self.terminalize_past_due_runtime_lease(&fence, row)?;
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

    // ---------------------------------------------------------------------
    // Control-reserve axis proof (F-LOG-KERNEL-4, #903; cases T13..T17 and
    // T21..T23).
    //
    // Every premise below names a PRODUCTION subject and reads a value that
    // subject produced. Some operands are fixture-supplied INPUTS to a
    // production subject rather than things that subject emitted: the control
    // requests, the lease holder states named at the distinctness claims, and
    // the hand-listed `TransportError` value array are all built here and then
    // handed to a production owner. What is claimed is never a comparison of
    // two objects this module invented for its own comparison.
    //   * `KernelServiceError` / `TransportError` results come out of the real
    //     `KernelService`, `PeerIdentity` and `KernelControlRequest` owners;
    //   * the reserve counters come from the composition's own runtime port and
    //     front door, and the rendered `kernel.*` records come from the real
    //     #895 facade through the subscriber `install_diagnostic_capture()` installs;
    //   * absence claims scan the whole captured `eliot_kernel::diagnostics`
    //     surface of the measured step, never a hand-listed string set, and
    //     every absence is preceded by a positive count on the same surface.
    //
    // These are the platform-independent tier: nothing between here and the
    // closing brace is `#[cfg]`-gated, so all seven tests build and run on a
    // non-Windows target. #903 defers the `#[cfg(windows)]`-only kernel-owner
    // and daemon-launch execution to the platform-gated tier, so nothing here
    // proves live cutover, real owner evidence, or real reserve recovery.
    // ---------------------------------------------------------------------

    /// One rendered `#895` facade record, read back off the emission itself.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct CapturedRecord {
        event: String,
        outcome: String,
        code: String,
        capacity: String,
        /// The exact, sorted set of field names the producer emitted on this
        /// record. This is what makes a RENAMED field red: the four typed
        /// fields above cannot distinguish "absent" from "renamed", because
        /// absent is legal for three of the four, but the key set cannot.
        fields: Vec<String>,
        /// Exact rendered field values recorded from the event itself.
        values: std::collections::BTreeMap<String, String>,
        request_id: String,
    }

    /// The operation identity the facade published for one span
    /// (`kernel_diagnostics.rs::operation_context`, :647).
    #[derive(Clone, Debug, Default)]
    struct CapturedSpan {
        request_id: String,
    }

    #[derive(Default)]
    struct FieldCapture {
        fields: std::collections::BTreeMap<String, String>,
    }

    impl tracing::field::Visit for FieldCapture {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.fields
                .insert(field.name().to_owned(), value.to_owned());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            // A `Debug` rendering of a string field carries its quotes; the
            // captured surface stores the rendered field text itself.
            let rendered = format!("{value:?}");
            self.fields.insert(
                field.name().to_owned(),
                rendered.trim_matches('"').to_owned(),
            );
        }
    }

    /// Captures the facade's whole rendered surface for the measured step.
    struct DiagnosticCaptureLayer {
        records: std::sync::Arc<std::sync::Mutex<Vec<CapturedRecord>>>,
    }

    impl<S> tracing_subscriber::Layer<S> for DiagnosticCaptureLayer
    where
        S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
    {
        fn on_new_span(
            &self,
            attributes: &tracing::span::Attributes<'_>,
            id: &tracing::span::Id,
            context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = FieldCapture::default();
            attributes.record(&mut visitor);
            if let Some(span) = context.span(id) {
                span.extensions_mut().insert(CapturedSpan {
                    request_id: visitor
                        .fields
                        .get("request_id")
                        .cloned()
                        .unwrap_or_default(),
                });
            }
        }

        /// `control_plane.rs:261` re-records `request_id` on the live span
        /// after the request validated, so the captured operation identity has
        /// to follow the record, not only the span declaration.
        fn on_record(
            &self,
            id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = FieldCapture::default();
            values.record(&mut visitor);
            if let Some(span) = context.span(id)
                && let Some(captured) = span.extensions_mut().get_mut::<CapturedSpan>()
                && let Some(request_id) = visitor.fields.get("request_id")
            {
                captured.request_id = request_id.clone();
            }
        }

        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if event.metadata().target() != crate::kernel_diagnostics::KERNEL_DIAGNOSTICS_TARGET {
                return;
            }
            let mut visitor = FieldCapture::default();
            event.record(&mut visitor);
            let request_id = context
                .event_span(event)
                .and_then(|span| {
                    span.extensions()
                        .get::<CapturedSpan>()
                        .map(|captured| captured.request_id.clone())
                })
                .unwrap_or_default();
            // A missing field reads as the empty string, and that is CORRECT
            // rather than convenient: `observe_control` authors only `event` and
            // `outcome` (:39-45) and `observe_control_capacity` only `event` and
            // `capacity` (:120-125), and `assert_capacity_records` below ASSERTS
            // that a capacity record's `outcome` and `code` are empty. Panicking
            // on absence therefore turned every capture-window test red while
            // never reaching the rename case it was meant to catch.
            //
            // The rename case is caught by CONTENT instead: `fields` carries the
            // exact key set the producer emitted, and `assert_capacity_records`
            // compares it, so a renamed field changes the expected key set and
            // goes red there. SCOPE, stated so the next reader does not overclaim
            // it: the capacity assertion and the focused lease/resume observer
            // tests compare their own exact key sets; there is no generic
            // key-set assertion for every `observe_control` record.
            //
            // "AUTHORED" is the operative word, and the emitted set is one key
            // LARGER than the authored one: both producers pass a format string
            // to `tracing::info!`, and the macro turns it into a field named
            // `message`. `Event::record` visits every field including that one,
            // so a capacity record's key set is `capacity`, `event`, `message`.
            //
            // WHICH MACRO ARM, so the next reader follows the one this call
            // actually takes. `info!(target: T, event = .., capacity = .., "s")`
            // has no braces and no `name:`/`parent:`, so it matches the
            // `target:` arm at `src/macros.rs:1986` and then the field-list arm at
            // `:671` - NOT the `event!(.., {..}, $args)` arm at `:660`, which is
            // the equivalent statement for the BRACE form and is easy to cite by
            // mistake. The field named `message` is synthesised by the
            // `fieldset!` fallback at `:3218-3221` and its value by the
            // `valueset_all!` fallback at `:2965-2968`; both prepend it in the
            // same position. `target:` is METADATA, not a field, which is why
            // there is no fourth key. Pinned by Cargo.lock to tracing 0.1.44.
            // An expectation written from
            // the source call alone omits `message` and is therefore false on
            // every run - which is what the first version of this assertion did.
            let field = |name: &str| visitor.fields.get(name).cloned().unwrap_or_default();
            let values = visitor.fields.clone();
            if let Ok(mut records) = self.records.lock() {
                let mut fields: Vec<String> = visitor.fields.keys().cloned().collect();
                fields.sort();
                records.push(CapturedRecord {
                    event: field("event"),
                    outcome: field("outcome"),
                    code: field("code"),
                    capacity: field("capacity"),
                    fields,
                    values,
                    request_id,
                });
            }
        }
    }

    /// Scoped capture of the facade surface; the guard keeps the scoped
    /// subscriber installed for exactly the measured step.
    struct DiagnosticCapture {
        records: std::sync::Arc<std::sync::Mutex<Vec<CapturedRecord>>>,
        _guard: tracing::subscriber::DefaultGuard,
    }

    impl DiagnosticCapture {
        /// Returns and clears everything the facade rendered so far.
        fn take(&self) -> Vec<CapturedRecord> {
            self.records
                .lock()
                .map(|mut records| std::mem::take(&mut *records))
                .unwrap_or_default()
        }
    }

    fn install_diagnostic_capture() -> DiagnosticCapture {
        use tracing_subscriber::layer::SubscriberExt;

        let records = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(DiagnosticCaptureLayer {
            records: std::sync::Arc::clone(&records),
        });
        DiagnosticCapture {
            records,
            _guard: tracing::subscriber::set_default(subscriber),
        }
    }

    fn assert_bounded_observation(
        record: &CapturedRecord,
        event: &str,
        outcome: &str,
        message: &str,
    ) {
        assert_eq!(record.event, event);
        assert_eq!(record.outcome, outcome);
        assert_eq!(
            record.fields,
            vec![
                "event".to_owned(),
                "message".to_owned(),
                "outcome".to_owned(),
            ]
        );
        assert_eq!(record.values.len(), 3);
        assert_eq!(record.values.get("message").map(String::as_str), Some(message));
        assert!(record.code.is_empty());
        assert!(record.capacity.is_empty());
        assert!(record.request_id.is_empty());
    }

    /// Counts the whole captured surface for one event name.
    fn event_count(records: &[CapturedRecord], event: &str) -> usize {
        records
            .iter()
            .filter(|record| record.event == event)
            .count()
    }

    /// Returns the one record the captured surface carries for `event`.
    fn find_event<'records>(
        records: &'records [CapturedRecord],
        event: &str,
    ) -> &'records CapturedRecord {
        records
            .iter()
            .find(|record| record.event == event)
            .unwrap_or_else(|| panic!("the captured surface must render {event}"))
    }

    /// Every terminal the captured surface rendered, read off its own record.
    fn terminal_records(records: &[CapturedRecord]) -> Vec<&CapturedRecord> {
        records
            .iter()
            .filter(|record| record.event == "kernel.terminal_error")
            .collect()
    }

    /// The production error value of a refused reserve or transition call.
    fn reserve_refusal<T>(
        result: Result<T, KernelServiceError>,
        refusal: &str,
    ) -> Result<KernelServiceError, Box<dyn std::error::Error>> {
        match result {
            Ok(_) => Err(std::io::Error::other(refusal).into()),
            Err(error) => Ok(error),
        }
    }

    fn reserve_test_root(name: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-control-reserve-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root)?;
        Ok(root)
    }

    #[test]
    fn unreadable_shutdown_state_is_reported_without_closing_runtime()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = reserve_test_root("shutdown-load-failure")?;
        let kernel = KernelComposition::new(KernelConfig::new(&root))?;
        let state_path = root
            .join(".eliot")
            .join("kernel-shutdown-drain.json");
        std::fs::create_dir_all(
            state_path
                .parent()
                .ok_or_else(|| std::io::Error::other("shutdown state path has parent"))?,
        )?;
        let canary = "shutdown-state-load-canary-903";
        std::fs::write(&state_path, canary)?;

        let capture = install_diagnostic_capture();
        assert!(!kernel.request_shutdown());
        let records = capture.take();
        assert_eq!(records.len(), 1);
        assert_bounded_observation(
            &records[0],
            "kernel.control.drain_request_failed",
            "unavailable",
            "control plane observation",
        );
        assert!(
            !format!("{records:?}").contains(canary),
            "load failure details stay out of the bounded observation"
        );
        assert!(
            !kernel.runtime.shutdown_handle().is_requested(),
            "a failed durable load must not close runtime admission"
        );
        assert_eq!(std::fs::read_to_string(&state_path)?, canary);

        drop(capture);
        drop(kernel);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn shutdown_state_replace_failure_is_reported_without_closing_runtime()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = reserve_test_root("shutdown-persist-failure")?;
        let kernel = KernelComposition::new(KernelConfig::new(&root))?;
        let state_path = root
            .join(".eliot")
            .join("kernel-shutdown-drain.json");
        std::fs::create_dir_all(
            state_path
                .parent()
                .ok_or_else(|| std::io::Error::other("shutdown state path has parent"))?,
        )?;
        // Seed the process-wide owner while its target is absent. The cached
        // coordinator then reaches the real persist/replace path below.
        let coordinator = crate::coordinator_for(&root).map_err(std::io::Error::other)?;
        drop(coordinator);
        std::fs::create_dir(&state_path)?;

        let capture = install_diagnostic_capture();
        assert!(!kernel.request_shutdown());
        let records = capture.take();
        assert_eq!(records.len(), 2);
        assert_bounded_observation(
            &records[0],
            "kernel.shutdown.persist_failed",
            "rejected",
            "shutdown drain observation",
        );
        assert_bounded_observation(
            &records[1],
            "kernel.control.drain_request_failed",
            "unavailable",
            "control plane observation",
        );
        assert!(
            !format!("{records:?}").contains("shutdown-persist-failure"),
            "replace failure details stay out of the bounded observations"
        );
        assert!(
            !kernel.runtime.shutdown_handle().is_requested(),
            "a failed durable replace must not close runtime admission"
        );
        assert!(state_path.is_dir(), "the obstruction is the exact state target");

        drop(capture);
        drop(kernel);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// One nonce-free candidate contour that the production
    /// `HostKernelCandidateBinding::validate` admits.
    fn reserve_candidate()
    -> Result<eliot_kernel_service::HostKernelCandidateBinding, Box<dyn std::error::Error>> {
        use eliot_contracts::{AuthorityEpoch, EpochId, EpochLineageId};
        use eliot_kernel_service::{
            HostFileIdentity, HostJobBinding, HostJobIdentity, HostJobRoot, HostProcessBinding,
            RestartBudget,
        };
        use eliot_platform::PlatformHandle;
        use eliot_runtime_contracts::{
            RegisteredActivityWakePolicy, SupervisionJournalEpoch,
            SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
        };

        let incarnation = SupervisionLeaseIncarnationBinding {
            supervision_lease_scope_id: "eliot-supervision-scope:v1:903".to_owned(),
            supervision_lease_id: String::new(),
            scope_ref_digest: String::new(),
            installation_id: "installation-903".to_owned(),
            host_epoch: SupervisionJournalEpoch {
                lineage_id: "host-lineage-903".to_owned(),
                sequence: 1,
            },
            activation_id: "activation-903".to_owned(),
            activation_generation: SupervisionJournalEpoch {
                lineage_id: "activation-lineage-903".to_owned(),
                sequence: 1,
            },
            kernel_generation: SupervisionJournalEpoch {
                lineage_id: "kernel-lineage-903".to_owned(),
                sequence: 1,
            },
            watchdog_epoch: SupervisionJournalEpoch {
                lineage_id: "watchdog-lineage-903".to_owned(),
                sequence: 1,
            },
            observation_scope: SupervisionObservationScope {
                targets: vec!["eliot-kernel".to_owned()],
                sensor_profile: "eliot-runtime-live-v3".to_owned(),
                claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                governance_axis: "runtime-live-v3".to_owned(),
            },
            wake_policy: RegisteredActivityWakePolicy::Disabled,
            predecessor: None,
        }
        .with_derived_ids()?;
        Ok(eliot_kernel_service::HostKernelCandidateBinding {
            installation_id: PlatformHandle::new("installation-903")?,
            host_epoch: AuthorityEpoch::new(1)?,
            kernel_epoch: EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?,
                std::num::NonZeroU64::new(1)
                    .ok_or_else(|| std::io::Error::other("the test epoch is non-zero"))?,
            )?,
            activation_id: PlatformHandle::new("activation-903")?,
            artifact_hash: PlatformHandle::new("artifact-903")?,
            config_hash: PlatformHandle::new("config-903")?,
            job_object_id: PlatformHandle::new("Local\\Eliot-Host-Kernel-903")?,
            pipe_identity: PlatformHandle::new("\\\\.\\pipe\\eliot-kernel-903")?,
            host_process: HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: "C:\\eliot\\host.exe".to_owned(),
            },
            job_binding: HostJobBinding {
                job: HostJobIdentity {
                    name: "Local\\Eliot-Host-Kernel-903".to_owned(),
                },
                root: HostJobRoot {
                    process: HostProcessBinding {
                        process_id: 42,
                        start_time_100ns: 10,
                        image_path: "C:\\eliot\\kernel.exe".to_owned(),
                    },
                    executable: HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            supervision_incarnation: incarnation,
            restart_budget: RestartBudget::new(1, 1)?,
            agent_bridge_admission: None,
            containment_action: None,
        })
    }

    /// One authenticated control request whose canonical digest the production
    /// `KernelControlRequest::with_computed_digest` computed.
    fn reserve_control_request(
        candidate: &eliot_kernel_service::HostKernelCandidateBinding,
    ) -> Result<eliot_kernel_service::KernelControlRequest, Box<dyn std::error::Error>> {
        eliot_kernel_service::KernelControlRequest {
            wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
            wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
            message_id: eliot_platform::PlatformHandle::new("control-message-903")?,
            sequence: 7,
            peer_process_id: 7,
            generation: eliot_contracts::ResourceGeneration::genesis(),
            candidate: candidate.clone(),
            command: eliot_kernel_service::KernelControlCommand::ProbeReady,
            payload_digest: String::new(),
        }
        .with_computed_digest()
        .map_err(Into::into)
    }

    /// The composition's own service lock, borrowed for one production call.
    type ReserveService<'kernel> =
        std::sync::MutexGuard<'kernel, eliot_kernel_service::KernelService>;

    fn reserve_service(kernel: &KernelComposition) -> Result<ReserveService<'_>, std::io::Error> {
        kernel
            .service
            .lock()
            .map_err(|_| std::io::Error::other("composition service lock poisoned"))
    }

    /// Drives the composition's own `KernelService` to `Ready` through its
    /// published lifecycle API, so the reserve assertions below run against
    /// the real owner the control plane transitions.
    ///
    /// SYNTHETIC RECEIPT, DISCLOSED: `KernelReadyReceipt` is the owner's own
    /// output type and there is no second publisher of it on this surface, so the
    /// receipt handed to `publish_ready` below is authored by this fixture. The
    /// lifecycle calls are production's and the assertions are about the reserve
    /// the control plane then observes, never about the authenticity of the
    /// receipt's fields. The card's DEFER clause is what sanctions this:
    /// `#[cfg(windows)]`-only kernel-owner execution is out of proof scope.
    fn ready_reserve_composition(
        root: &std::path::Path,
    ) -> Result<KernelComposition, Box<dyn std::error::Error>> {
        let kernel = KernelComposition::new(KernelConfig::new(root))?;
        let candidate = reserve_candidate()?;
        let permit = eliot_kernel_service::KernelActivationPermit {
            operation_id: eliot_platform::PlatformHandle::new("activation-operation-903")?,
            candidate_binding_digest: candidate.compute_digest()?,
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: eliot_platform::PlatformHandle::new("journal-transaction-903")?,
            journal_sequence: 7,
            generation: eliot_contracts::ResourceGeneration::genesis(),
            authority_epoch: candidate.kernel_epoch.clone(),
            activation_nonce: eliot_platform::KernelActivationNonce::new(
                eliot_platform::PlatformHandle::new("a".repeat(64))?,
            )?,
        };
        {
            let mut service = reserve_service(&kernel)?;
            service.reconcile(candidate.clone())?;
            service.apply(eliot_kernel_service::KernelControlCommand::Shadow)?;
            service.apply(eliot_kernel_service::KernelControlCommand::PrepareHandoff)?;
            let activation = service.activate_permit(
                &permit,
                eliot_contracts::ResourceGeneration::genesis(),
                "c".repeat(64),
            )?;
            service.publish_ready(eliot_kernel_service::KernelReadyReceipt {
                activation_id: candidate.activation_id.clone(),
                activation_operation_id: activation.operation_id.clone(),
                activation_nonce_digest: activation.activation_nonce_digest.clone(),
                process: eliot_kernel_service::ProcessObservation {
                    process_id: eliot_platform::PlatformHandle::new("pid:42:start:10")?,
                    job_object_id: candidate.job_object_id.clone(),
                    state: eliot_runtime_contracts::ServiceProcessState::Ready,
                    health: eliot_runtime_contracts::HealthVector::healthy(),
                    evidence_refs: vec![eliot_platform::PlatformHandle::new("process-evidence")?],
                },
                health: eliot_runtime_contracts::HealthVector::healthy(),
                evidence_refs: vec![eliot_platform::PlatformHandle::new("ready-903")?],
            })?;
        }
        Ok(kernel)
    }

    /// The bounded capacity record a read rendered must carry the port value
    /// and must not carry an outcome or a terminal claim.
    fn assert_capacity_records(
        records: &[CapturedRecord],
        expected_capacity: usize,
        expected_records: usize,
    ) {
        let observed: Vec<&CapturedRecord> = records
            .iter()
            .filter(|record| record.event == "kernel.control.capacity_observed")
            .collect();
        assert_eq!(
            observed.len(),
            expected_records,
            "each observation renders exactly one bounded capacity record"
        );
        for record in observed {
            assert_eq!(
                record.capacity,
                expected_capacity.to_string(),
                "the rendered count is the port value, not an invented number"
            );
            assert!(
                record.outcome.is_empty() && record.code.is_empty(),
                "a capacity observation carries no outcome and no terminal claim"
            );
            // The producer's own key set, compared rather than trusted: a
            // renamed `capacity` or `event` field changes this vector, which is
            // what the absent-field read above cannot see. `message` is present
            // because `tracing::info!` synthesises it from the format string
            // (tracing-0.1.44 `src/macros.rs:660`), not because any producer
            // authored it; it is listed so the expectation stays the EXACT
            // emitted set rather than a hand-picked subset.
            assert_eq!(
                record.fields,
                vec![
                    "capacity".to_owned(),
                    "event".to_owned(),
                    "message".to_owned(),
                ],
                "the capacity observation must emit exactly the keys its owner writes"
            );
        }
    }

    /// A received control request is recorded once, never admitted, refused
    /// before any lifecycle-transition attempt, and denied under exactly one
    /// terminal bound to the operation the denial itself names. Every premise
    /// reads the rendered record or the production error value; nothing here
    /// compares two objects this module built for itself.
    ///
    /// The `transition_failed` absence is what pins the peer gate at
    /// `control_plane.rs:319` BEFORE the transition gateway at `:993`: a
    /// boundary that reached the gateway would render a `transition_failed`
    /// per refused request and still leave `terminal_records` at 1, because
    /// `:993` passes `emit_terminal = false`.
    fn assert_request_denied_not_admitted(
        records: &[CapturedRecord],
        expected_code: &str,
        expected_request_id: &str,
    ) {
        assert_eq!(
            event_count(records, "kernel.control.request_received"),
            1,
            "the boundary records the request exactly once"
        );
        assert_eq!(
            find_event(records, "kernel.control.request_received").outcome,
            "attempt",
            "a received request is an attempt, never an admission"
        );
        assert_eq!(
            event_count(records, "kernel.control.request_admitted"),
            0,
            "the whole captured surface must render no admission for a refused request"
        );
        assert_eq!(
            event_count(records, "kernel.control.transition_failed"),
            0,
            "the refused request must never reach the transition gateway"
        );
        assert_eq!(
            event_count(records, "kernel.control.transition_committed"),
            0,
            "the refused request must never commit a lifecycle transition"
        );
        assert_eq!(
            event_count(records, "kernel.control.request_denied"),
            1,
            "the boundary records the denial exactly once"
        );
        let denied = find_event(records, "kernel.control.request_denied");
        assert_eq!(denied.outcome, "rejected");
        let terminals = terminal_records(records);
        assert_eq!(
            terminals.len(),
            1,
            "one underlying failed operation has one designated terminal"
        );
        assert_eq!(terminals[0].code, expected_code);
        assert_eq!(
            terminals[0].request_id, expected_request_id,
            "the terminal must carry the operation its own record names"
        );
        assert_eq!(terminals[0].request_id, denied.request_id);
    }

    /// T13 and T23.
    ///
    /// I14.20 (I14-20:86-87), "Ready work admission":
    /// `BLOCKED_DEPENDENCY → READY`,
    /// `READY → ADMITTED | DEFERRED_CAPACITY |
    /// CANCELLED | STALE` - a received request is a separate machine state
    /// from an admission. I14.20 (I14-20:81) also states "`REOPENED` is a new
    /// lifecycle revision, not a rewrite of the prior `FinishDecision`", the
    /// same discipline this boundary keeps for a changed payload under one
    /// operation identity. I1.8 (I01-08:18): "No component alone can invent
    /// semantics, authorize them and commit them."
    ///
    /// Production comparisons:
    /// * `control_plane.rs:267` renders `kernel.control.request_received`
    ///   ("attempt") before any admission check, while `:273` is the only
    ///   renderer of `kernel.control.request_admitted` and is reachable only
    ///   from an `Ok` response;
    /// * `control_plane.rs:277` renders the denial ("rejected") and `:291-296`
    ///   emits the one terminal under the same operation span;
    /// * `crates/kernel/eliot-kernel-service/src/protocol.rs:1573-1580` refuses
    ///   a changed same-operation payload digest, and `:1484` is the production
    ///   `validate` both cases are measured against;
    /// * `control_plane.rs:318` maps that refusal to
    ///   `TransportError::SessionFenced`, and `control_plane.rs:319` refuses a
    ///   composition that cannot prove peer identity;
    /// * `crates/kernel/eliot-kernel-service/src/lifecycle.rs:1396` is the
    ///   reserve acquisition neither refused request reaches.
    ///
    /// LIMIT (T13, PARTIAL): only the negative `request_admitted` leg runs.
    /// `kernel.control.request_admitted` at `control_plane.rs:273` is never
    /// executed anywhere in this module - it is only ever asserted `== 0`.
    /// Reaching it needs a `validate()`-passing request, a proven
    /// `peer.process_binding()`, agreement on sequence, peer process id, pipe
    /// identity, process id and start time and image path
    /// (`control_plane.rs:323-331`), and on Windows additionally
    /// `validate_candidate_process_binding` (`control_plane.rs:332-334`). The
    /// `PeerIdentity::Unavailable` fixture short-circuits at
    /// `control_plane.rs:319`, so the admitted leg is unreachable from here.
    ///
    /// LIMIT (T23, PARTIAL): the same-operation conflict IS typed below the
    /// boundary - `KernelServiceError::InvalidField { field:
    /// "control.payload_digest" }` from
    /// `crates/kernel/eliot-kernel-service/src/protocol.rs:1573-1580`, asserted
    /// directly below - but it collapses at the boundary to
    /// `TransportError::SessionFenced` (`control_plane.rs:316-318`), the same
    /// code as 60 other `SessionFenced` sites in
    /// `apply_control_request_inner`. So what is proved is that the typed cause
    /// exists and that the boundary's refusal code is stable, not that the
    /// boundary preserves the conflict's distinct identity.
    #[tokio::test]
    async fn control_request_is_recorded_and_denied_without_becoming_a_reserve_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = reserve_test_root("request-vs-admission")?;
        let kernel = KernelComposition::new(KernelConfig::new(&root))?;
        let candidate = reserve_candidate()?;
        let (state_before, reserve_before) = {
            let service = reserve_service(&kernel)?;
            (service.state(), service.available_control())
        };

        // The exact request Host would send for this operation: its canonical
        // digest is the one production computed (`protocol.rs:1478`).
        let exact = reserve_control_request(&candidate)?;
        // The same operation identity with a changed payload: identical
        // `message_id` and `sequence`, different canonical digest.
        let mut changed = exact.clone();
        changed.payload_digest = "d".repeat(64);
        let changed_refusal = reserve_refusal(
            changed.validate(),
            "a changed same-operation payload must be refused",
        )?;
        assert!(
            matches!(
                changed_refusal,
                KernelServiceError::InvalidField {
                    field: "control.payload_digest",
                    ..
                }
            ),
            "production names the changed-payload field"
        );
        assert_ne!(exact.payload_digest, changed.payload_digest);

        let unproven_peer = PeerIdentity::Unavailable {
            reason: eliot_ipc::PeerIdentityUnavailable::ProviderProofNotComposed,
        };
        let capture = install_diagnostic_capture();

        let exact_result = kernel
            .apply_control_request(exact.clone(), &unproven_peer, exact.sequence)
            .await;
        assert_eq!(
            exact_result,
            Err(TransportError::PeerIdentityUnavailable),
            "a validated request is still refused when peer identity is unproven"
        );
        let exact_records = capture.take();
        assert_request_denied_not_admitted(
            &exact_records,
            control_request_terminal_code(&TransportError::PeerIdentityUnavailable),
            exact.message_id.as_str(),
        );

        let changed_result = kernel
            .apply_control_request(changed, &unproven_peer, exact.sequence)
            .await;
        assert_eq!(
            changed_result,
            Err(TransportError::SessionFenced),
            "the changed payload is refused before the peer gate"
        );
        let changed_records = capture.take();
        // An unvalidated request never publishes an operation identity, so the
        // terminal cannot name a request the boundary never accepted
        // (`control_plane.rs:248` and `:259-266`).
        assert_request_denied_not_admitted(
            &changed_records,
            control_request_terminal_code(&TransportError::SessionFenced),
            "unavailable",
        );

        // Neither refusal is a reserve admission: the lifecycle owner and the
        // front-door reserve are byte-identical before and after both steps.
        let service = reserve_service(&kernel)?;
        assert_eq!(service.state(), state_before);
        assert_eq!(service.available_control(), reserve_before);
        drop(service);
        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    /// T21.
    ///
    /// I14.21 (I14-21:4, :8): "connection fails during commit; ... if unknown →
    /// pause Ordering Scope, preserve operation and open Problem State" - never
    /// a blind duplicate effect. I14.20 (I14-20:36-37): "... ambiguous effect
    /// remains `UNKNOWN_OUTCOME` until reconciliation produces a final
    /// receipt/disposition". I16.17 (I16-17:12) requires the emitted record to
    /// carry "facts/unknowns/conflicts", and I16-17 (I16-17:34): "Operational
    /// logs never become verifier evidence by themselves", so the unknown stays
    /// unknown under its own code.
    ///
    /// LIMIT: only the code table is proved for this case. Nothing in this
    /// module ever executes `apply_control_request` with an
    /// `UnknownOutcome`-producing subject, so no captured-surface leg of T21
    /// runs; `TransportError::UnknownOutcome` is asserted here as a value
    /// handed to the two production functions, never as one production
    /// produced. The `ControlRequestFailure::from` leg is likewise a
    /// hand-built input, not an observed boundary outcome.
    ///
    /// Production comparisons: `control_plane.rs:87` renders the stable
    /// `control_unknown_outcome` code for `TransportError::UnknownOutcome`;
    /// `control_plane.rs:106-110` is the production conversion that must keep
    /// that exact variant instead of synthesising an outcome;
    /// `control_plane.rs:74-95` is the only request-boundary code table, and
    /// `lost_control_expected_codes()` supplies one value per variant the code table names today.
    #[test]
    fn lost_control_response_stays_unknown_under_its_own_terminal() {
        assert_eq!(
            control_request_terminal_code(&TransportError::UnknownOutcome),
            "control_unknown_outcome",
            "control_plane.rs:87 is the stable code for a lost response"
        );
        assert!(
            matches!(
                ControlRequestFailure::from(TransportError::UnknownOutcome),
                ControlRequestFailure::Transport(TransportError::UnknownOutcome)
            ),
            "control_plane.rs:106-110 must preserve the exact variant"
        );

        // One production value per `TransportError` variant this module lists. The
        // `lost_control_expected_codes()` list is hand-listed, so it does NOT
        // establish the table's completeness: a `TransportError` variant added to
        // production would never reach it. What is established is that every
        // variant listed here maps to a stable code, that no refusal code reads
        // as success, and that the one collision among them is declared.
        let refusals = [
            TransportError::InvalidLimits,
            TransportError::UnauthenticatedPeer,
            TransportError::PeerIdentityUnavailable,
            TransportError::Protocol(eliot_protocol::ProtocolError::InvalidField {
                field: "control.frame",
                reason: "fixed test value",
            }),
            TransportError::SessionFenced,
            TransportError::Backpressure,
            TransportError::AttributedBackpressure(eliot_ipc::BackpressureSignal::new(
                "control-reserve-bytes",
                "retry-under-same-identity",
                "normal-lane-work",
            )),
            TransportError::Timeout,
            TransportError::Cancelled,
            TransportError::InvalidPipeName,
            TransportError::UnknownOutcome,
            TransportError::Io("pipe-canary".to_owned()),
            TransportError::PlanGap {
                dependency: "dep",
                reason: "reason",
            },
            TransportError::UnknownRequest,
            TransportError::IdentityConflict,
            TransportError::LegacyCorrelationUnresolved,
            TransportError::RegistryFull,
        ];
        let expected_codes = lost_control_expected_codes();
        assert_eq!(
            expected_codes.len(),
            refusals.len(),
            "the expected-code list must stay aligned with the listed refusals, or \
             the per-refusal presence assertion below would bind the wrong pair"
        );
        let mut codes = std::collections::BTreeSet::new();
        for (refusal_index, refusal) in refusals.iter().enumerate() {
            let code = control_request_terminal_code(refusal);
            let expected = expected_codes[refusal_index];
            assert_eq!(
                code, expected,
                "each listed refusal must render the code `lost_control_expected_codes()` \
                 declares for it at the same index; an empty or blank code would make \
                 the success-token absence below vacuous"
            );
            for success_token in ["success", "admitted", "committed", "ok", "ready"] {
                assert!(
                    !code.contains(success_token),
                    "a refusal code must never read as a success claim: {code}"
                );
            }
            codes.insert(code);
        }
        assert_eq!(
            codes.len(),
            refusals.len() - 1,
            "exactly one declared arm shares a code across the 17 listed variants"
        );
        // The count above cannot say WHICH pair collides, so the collision is
        // asserted directly against the production arm.
        assert_eq!(
            control_request_terminal_code(&TransportError::Backpressure),
            control_request_terminal_code(&TransportError::AttributedBackpressure(
                eliot_ipc::BackpressureSignal::new(
                    "control-reserve-bytes",
                    "retry-under-same-identity",
                    "normal-lane-work",
                )
            )),
            "control_plane.rs:81-83 is the one arm that shares a code (bare and \
             attributed backpressure)"
        );
        // A lost response is not a fenced session: the two stay typed apart, so
        // an unknown outcome is never replayed as a fresh denial.
        assert_ne!(
            control_request_terminal_code(&TransportError::UnknownOutcome),
            control_request_terminal_code(&TransportError::SessionFenced)
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::IdentityConflict),
            "control_identity_conflict",
            "control_plane.rs:91 keeps a same-operation conflict typed"
        );
    }

    /// T14.
    ///
    /// I14.3 (I14-03:27): "Normal workload cannot consume it". I14.24
    /// (I14-24:43), truncated after the `control/recovery remains` cell:
    /// "Control Reserve
    /// threatened | stop normal/background admission and shed rebuildable work |
    /// control/recovery remains" - which only holds if a diagnostic read
    /// neither consumes the reserve nor reports normal capacity as protected.
    ///
    /// LIMIT: the #903 checklist item 14 reads "normal work cannot be promoted
    /// to protected control by diagnostics". What is executed is the promotion
    /// path in the one direction production exposes: the protected read is
    /// shown not to consume the reserve, and saturating the control reserve is
    /// shown not to touch the normal lane (`Runtime::spawn`, the normal-lane
    /// admission at `crates/kernel/eliot-runtime/src/lib.rs:878`). Nothing here
    /// measures the reverse direction, because production exposes no API that
    /// admits a `Data`-class workload into the `ProtectedControl` lane.
    ///
    /// Production comparisons: `control_plane.rs:1547-1552` reads
    /// `Runtime::available_capacity(ExecutionClass::ProtectedControl)`
    /// (`crates/kernel/eliot-runtime/src/lib.rs:1006`) and returns it, and
    /// `control_plane.rs:116-126` renders the bounded `kernel.control.capacity_observed`
    /// record; `crates/kernel/eliot-runtime/src/lib.rs:891-902` and `:904` are
    /// the protected-slot admission path as this workspace calls it -
    /// `spawn_in` is `pub` on the public `Runtime`, so the workspace call
    /// sites at `:887` and `:900` are a workspace fact, not an ownership fact -
    /// `:878` is the normal-lane admission path; the composition's own reserve
    /// sizes are `bins/eliot-kernel/src/composition_bootstrap.rs:1882-1883`.
    #[tokio::test]
    async fn control_capacity_observation_never_acquires_the_protected_reserve()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = reserve_test_root("capacity-read")?;
        let kernel = KernelComposition::new(KernelConfig::new(&root))?;
        let capture = install_diagnostic_capture();

        let observed = kernel.control_capacity();
        assert_eq!(
            observed, 1,
            "composition_bootstrap.rs:1883 fixes one protected control slot"
        );
        assert_eq!(
            observed,
            kernel
                .runtime
                .available_capacity(eliot_runtime::ExecutionClass::ProtectedControl),
            "control_plane.rs:1548-1550 must return the runtime port value unchanged"
        );
        let observed_records = capture.take();
        assert_capacity_records(&observed_records, observed, 1);

        // The read did not consume the reserve: every slot it reported can
        // still be admitted through the production protected spawn path.
        let notify = std::sync::Arc::new(tokio::sync::Notify::new());
        let mut handles = Vec::new();
        for _ in 0..observed {
            let notify = std::sync::Arc::clone(&notify);
            let disposition = kernel.runtime.spawn_control(
                "control-reserve-observation-proof",
                move |_token| async move {
                    notify.notified().await;
                    Ok(())
                },
            );
            assert!(
                disposition.is_admitted(),
                "the reported capacity must still admit protected control work"
            );
            handles.push(disposition.into_handle().ok_or_else(|| {
                std::io::Error::other("an admitted disposition carries its handle")
            })?);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(
            kernel.control_capacity(),
            0,
            "the held protected slots are now consumed, and exhaustion is visible"
        );
        // NOT a duplicate of the assertion above, and it must not be removed as
        // one: this call is the SECOND `observe_control_capacity` emission in
        // this capture window, and `assert_capacity_records(..., 2)` below counts
        // exactly two rendered records. Deleting it leaves the count at 1 and
        // turns a correct run red at that assertion instead.
        assert_eq!(
            kernel.control_capacity(),
            0,
            "a repeated observation cannot acquire, refill or underflow the reserve"
        );
        let exhaustion_records = capture.take();
        assert_capacity_records(&exhaustion_records, 0, 2);

        // Normal work keeps its own lane: exhausting the control reserve leaves
        // the normal partition untouched, so the observation never promoted
        // normal work into protected control.
        assert_eq!(
            kernel
                .runtime
                .available_capacity(eliot_runtime::ExecutionClass::Data),
            4,
            "composition_bootstrap.rs:1882 fixes four normal slots"
        );
        assert!(
            kernel
                .runtime
                .spawn(
                    "normal-lane-observation-proof",
                    |_token| async move { Ok(()) }
                )
                .is_admitted(),
            "normal work stays admissible while the control reserve reads zero"
        );

        for handle in &handles {
            handle.cancellation().force_abort();
        }
        for handle in handles {
            let _ = handle.join().await;
        }
        assert_eq!(
            kernel.control_capacity(),
            observed,
            "released protected slots return to the reserve; the read never resized it"
        );
        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    /// T16.
    ///
    /// I14.24 (I14-24:43), the complete row: "Control Reserve
    /// threatened | stop normal/background admission and shed rebuildable work
    /// | control/recovery remains | release
    /// resources; identify runaway owner" - a degradation closes normal
    /// admission, not the protected lane and not the whole Kernel. I14.20
    /// (I14-20:11) keeps `READY ↔ DEGRADED` a named service state, and I13.11
    /// (I13-11:6, :9) requires the record to compile a problem model
    /// ("symptom/severity; ... exact evidence/log handles"), which is why the
    /// degradation and the total-failure classes keep separate stable codes.
    ///
    /// LIMIT: the `DEGRADED` vs `FAILED` separation asserted below rests on
    /// PRODUCTION, not on I14.20. I14-20:13 lists
    /// `STARTING | RECOVERING | READY | DEGRADED | QUIESCING → FAILED`, so the
    /// vocabulary expressly PERMITS a `DEGRADED` service to transition to
    /// `FAILED`; it does not declare the two mutually exclusive. What is proved
    /// here is the narrower, observable claim: one `Degrade` transition commits
    /// a `Degraded` state, emits no terminal, and leaves normal admission
    /// closed while protected control stays open. Whether a degraded service
    /// may later become `Failed` is not decided by this test.
    ///
    /// LIMIT: `KernelServiceError::Core` maps to `CONTROL_CORE` at
    /// `control_plane.rs:64`, and that mapping is asserted here against a
    /// production-constructed `Core` value, but no boundary assertion for it
    /// exists. `KernelService::apply` never constructs
    /// `KernelServiceError::Core`; production builds it only at
    /// `crates/kernel/eliot-kernel-service/src/lifecycle.rs:1444` (inside
    /// `issue_control_receipt`) and
    /// `crates/kernel/eliot-kernel-service/src/storage_replacement.rs:1745`,
    /// neither of which any command on the transition gateway dispatches to.
    /// Only the code table is proved for `Core`.
    ///
    /// Production comparisons: `control_plane.rs:175-210` is the transition
    /// wrapper under test; `control_plane.rs:52-65` is the code table;
    /// `crates/kernel/eliot-kernel-service/src/lifecycle.rs:1339` closes normal
    /// admission outside `Ready` and `:1384-1388` keeps protected control open
    /// in `Ready | Degraded`; the state values come from
    /// `crates/kernel/eliot-kernel-service/src/lifecycle.rs:69-92`.
    #[test]
    fn degraded_kernel_keeps_protected_control_open_and_is_not_a_total_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = reserve_test_root("degradation")?;
        let kernel = ready_reserve_composition(&root)?;
        let capture = install_diagnostic_capture();

        let degraded =
            kernel.apply_control(eliot_kernel_service::KernelControlCommand::Degrade(
                eliot_platform::PlatformHandle::new("reserve-degraded-903")?,
            ))?;
        assert_eq!(degraded, eliot_kernel_service::KernelServiceState::Degraded);
        let committed = capture.take();
        assert_eq!(
            event_count(&committed, "kernel.control.transition_committed"),
            1,
            "a degradation is a committed transition, not a failure"
        );
        assert_eq!(
            find_event(&committed, "kernel.control.transition_committed").outcome,
            "success"
        );
        assert!(
            terminal_records(&committed).is_empty(),
            "a degraded component must not report a terminal for the whole Kernel"
        );

        let service = reserve_service(&kernel)?;
        assert_eq!(
            service.state(),
            eliot_kernel_service::KernelServiceState::Degraded
        );
        assert_ne!(
            service.state(),
            eliot_kernel_service::KernelServiceState::Failed,
            "the degraded service state is not the whole-Kernel Failed state"
        );
        let normal_refusal = reserve_refusal(
            service.acquire_admission(),
            "normal admission must close while degraded",
        )?;
        assert!(matches!(
            normal_refusal,
            KernelServiceError::AdmissionClosed(eliot_kernel_service::KernelServiceState::Degraded)
        ));
        let protected = service.acquire_protected_control("drain:reserve-degraded-903")?;
        assert_eq!(protected.operation_id(), "drain:reserve-degraded-903");
        protected.release();

        // The stable codes keep the reserve degradation apart from the two
        // whole-Kernel failure classes.
        assert_eq!(
            control_transition_terminal_code(&normal_refusal),
            "CONTROL_ADMISSION_CLOSED"
        );
        assert_ne!(
            control_transition_terminal_code(&normal_refusal),
            control_transition_terminal_code(&KernelServiceError::Platform(
                "reserve degraded".to_owned()
            ))
        );
        assert_eq!(
            control_transition_terminal_code(&KernelServiceError::Platform(
                "reserve degraded".to_owned()
            )),
            "CONTROL_PLATFORM"
        );
        assert_eq!(
            control_transition_terminal_code(&KernelServiceError::Core(
                eliot_kernel_core::KernelError::InvalidField {
                    field: "control_reserve",
                    reason: "fixed test value",
                }
            )),
            "CONTROL_CORE"
        );
        drop(service);
        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    /// Readiness is never fabricated from capacity: a caller-shaped claim stays
    /// unproven and the captured surface renders no admission for it.
    fn assert_probe_readiness_not_fabricated(
        kernel: &KernelComposition,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let capture = install_diagnostic_capture();
        let probe = reserve_refusal(
            kernel.apply_control(eliot_kernel_service::KernelControlCommand::ProbeReady),
            "a caller-shaped readiness claim must stay unproven",
        )?;
        let records = capture.take();
        assert_eq!(event_count(&records, "kernel.control.transition_failed"), 1);
        assert_eq!(
            event_count(&records, "kernel.control.transition_committed"),
            0,
            "the whole captured surface must render no committed transition"
        );
        assert_eq!(
            event_count(&records, "kernel.control.request_admitted"),
            0,
            "the whole captured surface must render no admission"
        );
        let terminals = terminal_records(&records);
        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0].code, control_transition_terminal_code(&probe));
        assert_eq!(terminals[0].code, "CONTROL_READINESS_NOT_PROVEN");
        Ok(())
    }

    /// T15 and T17.
    ///
    /// I14.3 (I14-03:29): "Admission checks the exact bottleneck vector rather
    /// than one scalar percentage; exhaustion ... may independently close
    /// normal/background admission while preserving the applicable
    /// recovery/control lane. Each disposition names the exhausted resource
    /// and the work shed, deferred or quarantined." I14.20 (I14-20:91-94)
    /// "Admission reservation": `STAGED_INACTIVE → ACTIVE | RELEASED | EXPIRED |
    /// RECONCILING` - four dispositions, not two. I13.11 (I13-11:13) requires
    /// the brief to carry "current hypotheses and unknowns", so exhaustion is
    /// reported and readiness is never manufactured from it.
    ///
    /// LIMIT: this proves exhaustion is VISIBLE and readiness is not
    /// fabricated from it. It does not execute the four dispositions of the
    /// reservation machine above; `STAGED_INACTIVE`, `ACTIVE` and
    /// `RECONCILING` are not states this composition's reserve reaches. See the
    /// LIMIT on `runtime_lease_dispositions_stay_distinct_under_production_state_legality`
    /// for which words of the checklist's reserve-disposition item production
    /// does not represent at all.
    ///
    /// Production comparisons: `crates/kernel/eliot-kernel-service/src/lifecycle.rs:1396`
    /// is the protected acquisition, `:1443` is the only mapping that yields
    /// `KernelServiceError::ControlReserveExhausted`, and `control_plane.rs:62`
    /// renders it as `CONTROL_RESERVE_EXHAUSTED`;
    /// `crates/kernel/eliot-kernel-core/src/module/control_reserve_front_door.rs:1206-1210`
    /// is the legacy acquisition that saturates it;
    /// `crates/kernel/eliot-kernel-service/src/lifecycle.rs:628-633` is the
    /// refusal of a caller-shaped readiness claim - its own comment at `:629-630`
    /// reads "A wire command cannot carry a caller-shaped readiness receipt" -
    /// and `control_plane.rs:58` renders it;
    /// `crates/kernel/eliot-kernel-service/src/lifecycle.rs:500` is the state
    /// read that must stay unchanged across an exhaustion refusal.
    #[test]
    fn reserve_exhaustion_is_visible_without_fabricating_readiness()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = reserve_test_root("exhaustion")?;
        let kernel = ready_reserve_composition(&root)?;

        let mut held = Vec::new();
        let capacity = reserve_service(&kernel)?.available_control();
        assert_eq!(
            capacity, 4,
            "composition_bootstrap.rs:1765 builds the front door with four \
             protected slots (control_reserve_front_door.rs:1048)"
        );
        for index in 0..capacity {
            let lease = {
                let service = reserve_service(&kernel)?;
                service.acquire_protected_control(&format!("drain:reserve-exhaustion-{index}"))?
            };
            held.push(lease);
        }
        let service = reserve_service(&kernel)?;
        assert_eq!(
            service.available_control(),
            0,
            "every admitted lease consumed exactly one protected slot"
        );
        // A DIRECT call on the service owner. This call does not cross
        // `apply_control_with_terminal` (`control_plane.rs:183-210`), so nothing
        // here observes what the transition boundary would emit for it, and
        // deleting every `CONTROL_CORE` emission from the request/transition
        // boundary would go undetected by this case.
        let exhaustion = reserve_refusal(
            service.acquire_protected_control("drain:reserve-exhaustion-overflow"),
            "one admission past the reserve capacity must be refused",
        )?;
        assert!(
            matches!(
                exhaustion,
                KernelServiceError::Core(
                    eliot_kernel_core::KernelError::ProtectedReserveExhausted { .. }
                )
            ),
            "the typed protected exhaustion reaches the service owner"
        );
        // Exhaustion is a reserve disposition, not a lifecycle transition.
        assert_eq!(
            service.state(),
            eliot_kernel_service::KernelServiceState::Ready
        );
        assert_ne!(
            service.state(),
            eliot_kernel_service::KernelServiceState::Failed
        );
        assert_eq!(service.available_control(), 0);

        // The legacy issuance path names the exhausted reserve itself, so the
        // reserve-specific terminal exists and stays apart from the two
        // whole-Kernel failure codes.
        let legacy = reserve_refusal(
            service.issue_control_receipt(
                eliot_contracts::ContractId::new("reserve-exhaustion-903")?,
                eliot_kernel_core::RouteScope::new("control")?,
                0,
                None,
            ),
            "a saturated reserve must refuse a control receipt issuance",
        )?;
        assert!(matches!(
            legacy,
            KernelServiceError::ControlReserveExhausted
        ));
        assert_eq!(
            control_transition_terminal_code(&legacy),
            "CONTROL_RESERVE_EXHAUSTED"
        );
        assert_ne!(
            control_transition_terminal_code(&legacy),
            control_transition_terminal_code(&KernelServiceError::Platform(
                "reserve exhausted".to_owned()
            ))
        );
        assert_ne!(
            control_transition_terminal_code(&legacy),
            control_transition_terminal_code(&exhaustion)
        );

        // Released capacity returns to the reserve; the observation and the
        // refusal never resized it.
        drop(held);
        assert_eq!(service.available_control(), capacity);
        drop(service);

        // Readiness is never fabricated from capacity or from a release: the
        // probe stays refused and the captured surface renders no admission.
        assert_probe_readiness_not_fabricated(&kernel)?;
        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    /// T15 (runtime-lease dispositions) and the single-terminal discipline of
    /// the axis.
    ///
    /// The axis proved here is RUNTIME-LEASE state, not admission-reservation
    /// disposition. I14.20 (I14-20:91-94) "Admission reservation":
    /// `STAGED_INACTIVE → ACTIVE | RELEASED | EXPIRED |
    /// RECONCILING`, and (I14-20:99) "Release, expiry and recovery reuse the
    /// same reservation identity and produce a receipt". I14.3 (I14-03:29)
    /// requires every reserve disposition to name the exhausted resource and
    /// the work shed, deferred or quarantined. I1.8 (I01-08:18): "No component
    /// alone can invent semantics, authorize them and commit them."
    ///
    /// LIMIT: the checklist item reads "admitted/consumed/released/expired
    /// reserve distinct". Production does not represent the "admitted" or
    /// "consumed" words of that item: `CapacityClass`
    /// (`crates/foundation/eliot-runtime-contracts/src/control_reserve.rs:17-24`)
    /// has exactly three variants - `NormalWorkload`, `ProtectedControl`,
    /// `EmergencyLastResort` - and carries no admit/consume state; and
    /// `PermitTerminalDisposition`
    /// (`crates/foundation/eliot-runtime-contracts/src/control_reserve.rs:973-984`)
    /// has exactly five variants with no `Expired` member. `LeaseState::Expired`
    /// exists (`crates/foundation/eliot-runtime-contracts/src/lib.rs:1109`) but
    /// is a RUNTIME-LEASE state that no reserve permit terminal carries. This
    /// test therefore proves distinctness of the runtime-lease dispositions
    /// `Released | Expired | Revoked | Superseded` and of the five
    /// permit-terminal dispositions. It does not prove the checklist's
    /// four-word reserve-disposition item, and the "expired" word is proved
    /// only on the runtime-lease axis.
    ///
    /// Production comparisons: `control_plane.rs:1650-1659` is the terminal
    /// predicate over the lease states; `control_plane.rs:1632-1635` keeps the
    /// renewed, expired and superseded counts in separate bounded fields;
    /// `crates/foundation/eliot-runtime-contracts/src/lib.rs:1154-1186` is the
    /// production state legality that keeps the dispositions apart;
    /// `crates/foundation/eliot-runtime-contracts/src/control_reserve.rs:973-984`
    /// is the production permit-terminal vocabulary;
    /// `control_plane.rs:1684-1700` derives the one reservation identity.
    #[test]
    fn runtime_lease_dispositions_stay_distinct_under_production_state_legality()
    -> Result<(), Box<dyn std::error::Error>> {
        use eliot_runtime_contracts::{LeaseState, PermitTerminalDisposition};

        let candidate = reserve_candidate()?;
        let lease_id = runtime_lease_id_for_candidate(&candidate)?;
        assert_eq!(
            lease_id,
            format!(
                "runtime-lease:{}:activation-lineage-903:1",
                candidate.activation_id.as_str()
            ),
            "control_plane.rs:1694 derives one reservation identity"
        );
        let fence = StateFence::new(
            candidate.kernel_epoch.clone(),
            eliot_contracts::ResourceGeneration::genesis(),
        );
        let active = eliot_runtime_contracts::RuntimeLease {
            lease_id: lease_id.clone(),
            scope_ref: candidate.activation_id.as_str().to_owned(),
            authority_epoch: candidate.kernel_epoch.clone(),
            state_fence: fence,
            state: LeaseState::Active,
            expires_at_ms: 60_000,
        };

        // One active hold reaches four different dispositions. What is asserted is
        // that production's legality matrix admits each of them, returns the
        // requested state, and refuses the resurrection edges. It is
        // deliberately NOT asserted that the four resulting `state` values
        // differ from each other: `RuntimeLease::transition_to` assigns
        // `state: next` verbatim
        // (`crates/foundation/eliot-runtime-contracts/src/lib.rs:1183`), so a
        // pairwise `state` inequality here would compare two enum constants
        // this test itself named at the four `transition_to` call sites, and
        // would stay green with the whole legality matrix replaced by
        // `let legal = true;`. `LeaseState` is a plain fieldless enum
        // (`:1104-1114`) and exposes no production surface on which the four
        // could collide, so there is nothing further to assert here.
        let released = active.transition_to(LeaseState::Released)?;
        let expired = active.transition_to(LeaseState::Expired)?;
        let revoked = active.transition_to(LeaseState::Revoked)?;
        let superseded = active.transition_to(LeaseState::Superseded)?;
        assert_eq!(released.state, LeaseState::Released);
        assert_eq!(expired.state, LeaseState::Expired);
        assert_eq!(revoked.state, LeaseState::Revoked);
        assert_eq!(superseded.state, LeaseState::Superseded);
        // A terminal disposition is never re-admitted, so release and expiry
        // cannot silently become one another.
        assert!(released.transition_to(LeaseState::Active).is_err());
        assert!(expired.transition_to(LeaseState::Released).is_err());
        assert!(revoked.transition_to(LeaseState::Active).is_err());
        assert!(superseded.transition_to(LeaseState::Active).is_err());
        // The production predicate groups the terminal set but keeps the
        // non-terminal holds out of it. The two loops below together classify
        // all nine `LeaseState` variants production declares
        // (`crates/foundation/eliot-runtime-contracts/src/lib.rs:1104-1114`).
        for terminal in [
            LeaseState::Released,
            LeaseState::Expired,
            LeaseState::Revoked,
            LeaseState::Superseded,
            LeaseState::Closed,
        ] {
            assert!(
                runtime_lease_is_terminal(terminal),
                "control_plane.rs:1650 must accept {terminal:?} as terminal"
            );
        }
        for held in [
            LeaseState::Requested,
            LeaseState::Active,
            LeaseState::Expiring,
            LeaseState::Reconciling,
        ] {
            assert!(
                !runtime_lease_is_terminal(held),
                "control_plane.rs:1650 must keep {held:?} non-terminal"
            );
        }
        // Every permit-terminal disposition production declares
        // (`control_reserve.rs:973-984` - exactly five variants) is listed
        // here, and each keeps its own frozen contract name. The `insert`
        // assertion in the loop over them is the whole check; no separate
        // length equality could fail once it passes.
        let dispositions = [
            PermitTerminalDisposition::Released,
            PermitTerminalDisposition::ReconciledReleased,
            PermitTerminalDisposition::LeakSuspected,
            PermitTerminalDisposition::StaleOwner,
            PermitTerminalDisposition::Unknown,
        ];
        let mut contract_names = std::collections::BTreeSet::new();
        for disposition in dispositions {
            assert!(
                contract_names.insert(disposition.as_contract_str()),
                "every permit-terminal disposition keeps its own frozen name"
            );
        }
        assert_ne!(
            PermitTerminalDisposition::Unknown.as_contract_str(),
            PermitTerminalDisposition::Released.as_contract_str()
        );
        Ok(())
    }

    /// Single designated terminal per operation across the axis.
    ///
    /// The one designated terminal per operation is stated by the facade itself:
    /// `kernel_diagnostics.rs:683` (mirrored verbatim at
    /// `bins/eliot-host/src/host_diagnostics.rs:603`) - "One underlying failed
    /// operation yields exactly one terminal record here; the current span is
    /// preserved for existing callers". I1.8 (I01-08:18): Kernel verifies and
    /// commits; no component alone authorizes and commits.
    ///
    /// Production comparisons: `control_plane.rs:201-206` emits the terminal
    /// only for the caller that owns it, `control_plane.rs:993` is the
    /// request-boundary call that passes `false` because
    /// `ControlRequestFailure::Transition` (`:99-104`) hands terminal
    /// ownership back to the boundary, and
    /// `crates/kernel/eliot-kernel-service/src/lifecycle.rs:628-633` is the
    /// refusal both legs share, and its own comment at `:629-630` reads "A wire
    /// command cannot carry a caller-shaped readiness receipt".
    ///
    /// LIMIT: `owned` and `delegated` are the SAME `KernelControlCommand`
    /// value, so "one underlying failure" is supplied by this test rather than
    /// observed as two independent productions of one cause. What is proved is
    /// the ownership split - one terminal from the owning caller, none from the
    /// delegating one - not the convergence of two separately observed causes.
    #[test]
    fn one_failed_transition_emits_exactly_one_designated_terminal()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = reserve_test_root("single-terminal")?;
        let kernel = KernelComposition::new(KernelConfig::new(&root))?;
        // ORDERING CONSTRAINT: install the capture BEFORE creating `context`.
        // `DiagnosticCaptureLayer::on_new_span` only fires for spans declared
        // while the subscriber is installed, so a span created first has no
        // `CapturedSpan` extension, `on_event` finds `None` at the
        // `span.extensions()` read, and the delegated leg's records silently
        // fall back to `request_id == ""`. No assertion below depends on that
        // field, but any future one added here would read `""` for a
        // non-obvious reason. Installing first costs nothing and removes the
        // trap.
        let capture = install_diagnostic_capture();
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);

        // The transition gateway owns the terminal for its own operation.
        let owned = reserve_refusal(
            kernel.apply_control(eliot_kernel_service::KernelControlCommand::ProbeReady),
            "an unauthenticated readiness probe must be refused",
        )?;
        let owned_records = capture.take();
        assert_eq!(
            event_count(&owned_records, "kernel.control.transition_failed"),
            1
        );
        assert_eq!(
            find_event(&owned_records, "kernel.control.transition_failed").outcome,
            "rejected"
        );
        let owned_terminals = terminal_records(&owned_records);
        assert_eq!(
            owned_terminals.len(),
            1,
            "one failed transition yields exactly one terminal record"
        );
        // Anchored to the LITERAL, not only to the mapper that produced the
        // rendered code: `assert_eq!(code, control_transition_terminal_code(&x))`
        // compares production against itself and stays green if the
        // `ReadinessNotProven` arm is deleted or renamed. The literal is the same
        // one this module already pins for this same refusal at :3404.
        assert_eq!(
            owned_terminals[0].code,
            control_transition_terminal_code(&owned)
        );
        assert_eq!(
            owned_terminals[0].code, "CONTROL_READINESS_NOT_PROVEN",
            "the one terminal of this refused readiness probe is the stable readiness code"
        );

        // The same transition as a subordinate phase of a request: it keeps its
        // correlation record and emits no second terminal.
        let delegated = reserve_refusal(
            kernel.apply_control_with_terminal(
                eliot_kernel_service::KernelControlCommand::ProbeReady,
                false,
                &context,
            ),
            "the subordinate transition must be refused the same way",
        )?;
        let delegated_records = capture.take();
        assert_eq!(
            event_count(&delegated_records, "kernel.control.transition_failed"),
            1
        );
        assert!(
            terminal_records(&delegated_records).is_empty(),
            "a subordinate transition must not re-emit an owned terminal"
        );
        // One underlying failure, one cause and one code, whichever leg owns
        // the terminal.
        assert_eq!(
            control_transition_terminal_code(&owned),
            control_transition_terminal_code(&delegated)
        );
        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    // The code each of the 17 refusals listed by
    // `lost_control_response_stays_unknown_under_its_own_terminal` must render,
    // in the same order as that test lists them. The note that follows is that
    // test's own comment, moved here with each positional phrase rewritten to
    // name its target; "that test" throughout it means the test named here.
    //
    // Positive-before-absence, per element. `control_request_terminal_code`
    // returns `&'static str` and every arm of it is a non-empty table literal
    // (16 arms, 16 distinct literals, measured), so that test's success-token
    // absence loop cannot in fact be reached with an empty code. That is a
    // property of the signature and the table, not evidence that test
    // produces, so the code each listed refusal should render is asserted
    // first, on the same `code` binding, before any success token is tested
    // against it. This list restates those 17 refusals in the same order; an
    // arm that renders empty, blank, or another arm's text now fails on
    // presence instead of passing an absence that never had a value to bite
    // on. It still does NOT establish table completeness (see that test's
    // comment on its `refusals` list), and that test's `codes` set-count
    // assertion independently bounds the codes actually produced.
    fn lost_control_expected_codes() -> [&'static str; 17] {
        [
            "control_invalid_limits",
            "control_unauthenticated_peer",
            "control_peer_unavailable",
            "control_protocol",
            "control_fenced",
            "control_backpressure",
            "control_backpressure",
            "control_timeout",
            "control_cancelled",
            "control_invalid_pipe",
            "control_unknown_outcome",
            "control_io",
            "control_plan_gap",
            "control_unknown_request",
            "control_identity_conflict",
            "control_legacy_correlation_unresolved",
            "control_registry_full",
        ]
    }

    /// Narrow UnitProof for the observer and its typed owner count. It does
    /// not execute the Windows probe or activation callers at :749/:905; their
    /// caller-path proof remains TEST-PHASE.
    #[allow(
        clippy::too_many_lines,
        reason = "one focused proof keeps the owner transition, rendered fields, and non-interference assertion together"
    )]
    #[test]
    fn runtime_lease_tick_observation_uses_owner_expiry_count_without_changing_record() {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        use eliot_runtime_contracts::{LeaseState, RuntimeLease};

        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-runtime-lease-observation-{}-{}",
            std::process::id(),
            crate::unix_ms()
        ));
        std::fs::create_dir_all(&root).expect("runtime-lease observation test root");
        let kernel = KernelComposition::new(KernelConfig::new(&root))
            .expect("kernel composition for runtime-lease observation");
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("test epoch lineage"),
            std::num::NonZeroU64::new(1).expect("nonzero test epoch"),
        )
        .expect("test epoch");
        let fence = StateFence::new(
            epoch.clone(),
            ResourceGeneration::new(1).expect("test generation"),
        );
        let lease = RuntimeLease {
            lease_id: "runtime-lease:activation-canary-903:lineage:1".to_owned(),
            scope_ref: "activation-canary-903".to_owned(),
            authority_epoch: epoch,
            state_fence: fence.clone(),
            state: LeaseState::Active,
            expires_at_ms: 1,
        };
        kernel
            .generation_gateway
            .ors
            .record_runtime_lease_current(&lease)
            .expect("record valid active owner lease");

        // This is the production owner expiry path. It transitions and
        // persists the past-due Active row through ORS, and supplies the count
        // used to form the observer's typed result. The observer proof remains
        // narrower than either production caller at :749/:905.
        let expired = kernel
            .expire_past_due_runtime_leases(&fence, 2)
            .expect("expire the past-due owner row");
        assert_eq!(expired, 1);
        let outcome = RuntimeLeaseTickOutcome {
            expired,
            ..RuntimeLeaseTickOutcome::default()
        };
        let owner_rows = kernel
            .generation_gateway
            .ors
            .load_runtime_leases_by_state_fence(&fence)
            .expect("read the owner row after expiry");
        assert_eq!(owner_rows.len(), 1);
        assert_eq!(owner_rows[0].state, LeaseState::Expired);

        let capture = install_diagnostic_capture();
        observe_runtime_lease_tick(&outcome);
        let records = capture.take();
        assert_eq!(records.len(), 1, "one owner tick yields one event");
        assert_eq!(
            records[0].fields,
            vec![
                "event".to_owned(),
                "expired".to_owned(),
                "message".to_owned(),
                "renewed".to_owned(),
                "superseded".to_owned(),
            ]
        );
        assert_eq!(
            records[0].values,
            std::collections::BTreeMap::from([
                (
                    "event".to_owned(),
                    "kernel.control.runtime_lease_tick".to_owned(),
                ),
                ("expired".to_owned(), "1".to_owned()),
                (
                    "message".to_owned(),
                    "control plane runtime lease tick".to_owned(),
                ),
                ("renewed".to_owned(), "0".to_owned()),
                ("superseded".to_owned(), "0".to_owned()),
            ])
        );
        assert_eq!((outcome.renewed, outcome.expired, outcome.superseded), (0, 1, 0));
        assert_eq!(
            kernel
                .generation_gateway
                .ors
                .load_runtime_leases_by_state_fence(&fence)
                .expect("owner row remains readable after observation"),
            owner_rows,
            "observation must leave the ORS owner result unchanged"
        );
        assert!(
            !format!("{records:?}").contains("canary-903"),
            "runtime lease identity and scope stay out of the event"
        );

        drop(capture);
        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Narrow UnitProof for the observer fed by the actual contract result.
    /// It does not execute the production resume gate at :1133/:1183.
    #[test]
    fn resume_identity_gap_observation_uses_contract_verdict_order_and_preserves_result() {
        use eliot_contracts::{EpochId, EpochLineageId};
        use eliot_runtime_contracts::{
            ResumeBrokerIdentity, ResumeIdentityFamily, ResumeIdentitySnapshot,
            ResumeIdentityVerdict, ResumeProcessIdentity, revalidate_resume_identities,
        };

        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("test epoch lineage"),
            std::num::NonZeroU64::new(1).expect("nonzero test epoch"),
        )
        .expect("test epoch");
        let current = ResumeIdentitySnapshot {
            boot_id: "current-boot-canary-903".to_owned(),
            process: ResumeProcessIdentity {
                pid: 42,
                start_100ns: 987_654_321,
            },
            pipe_expectation: "current-pipe-canary-903".to_owned(),
            authority_epoch: epoch,
            broker: ResumeBrokerIdentity {
                windows_sid: "current-sid-canary-903".to_owned(),
                interactive_session_id: "current-session-canary-903".to_owned(),
                boot_session_id: "current-boot-session-canary-903".to_owned(),
                user_broker_epoch: 7,
            },
            lease_ids: vec!["runtime-lease:resume-canary-903:lineage:1".to_owned()],
        };
        let mut presented = current.clone();
        presented.boot_id = "presented-boot-canary-903".to_owned();
        presented.process.pid = 43;
        let revalidation = revalidate_resume_identities(&current, &presented)
            .expect("both typed resume snapshots are valid");
        assert_eq!(
            revalidation.coverage_gap_families,
            vec![ResumeIdentityFamily::Boot, ResumeIdentityFamily::Process]
        );
        assert_eq!(
            revalidation.verdicts,
            vec![
                (ResumeIdentityFamily::Boot, ResumeIdentityVerdict::Stale),
                (ResumeIdentityFamily::Process, ResumeIdentityVerdict::Stale),
                (ResumeIdentityFamily::Pipe, ResumeIdentityVerdict::Current),
                (ResumeIdentityFamily::Epoch, ResumeIdentityVerdict::Current),
                (ResumeIdentityFamily::Broker, ResumeIdentityVerdict::Current),
                (ResumeIdentityFamily::Lease, ResumeIdentityVerdict::Current),
            ]
        );
        let owner_result = revalidation.clone();

        let capture = install_diagnostic_capture();
        observe_resume_identity_gap(
            Some(&revalidation.verdicts),
            &revalidation.coverage_gap_families,
        );
        let records = capture.take();
        assert_eq!(records.len(), 2, "only the stale families are emitted");
        for (record, outcome) in records.iter().zip(["boot", "pid"]) {
            assert_eq!(record.event, "kernel.control.resume_identity_gap_observed");
            assert_eq!(record.outcome, outcome);
            assert_eq!(
                record.fields,
                vec!["event".to_owned(), "message".to_owned(), "outcome".to_owned()]
            );
            assert_eq!(
                record.values,
                std::collections::BTreeMap::from([
                    (
                        "event".to_owned(),
                        "kernel.control.resume_identity_gap_observed".to_owned(),
                    ),
                    ("message".to_owned(), "control plane observation".to_owned()),
                    ("outcome".to_owned(), outcome.to_owned()),
                ])
            );
        }
        assert_eq!(revalidation, owner_result, "observation cannot rewrite revalidation");
        assert!(
            !format!("{records:?}").contains("canary-903"),
            "resume observations contain family names, not identity values"
        );
    }
}
