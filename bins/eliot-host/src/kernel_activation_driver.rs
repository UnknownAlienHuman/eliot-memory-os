use super::{
    AppendReceipt, EpochTransition, HealthDimension, HostError, HostInstallationEpoch,
    HostKernelCandidateBinding, HostStateJournalService, HostStateRecord, JournalBackend,
    KernelActivationPermit, KernelActivationReceipt, KernelActivationState, KernelHandoffReceipt,
    KernelJobBinding, KernelReadyReceipt, KernelRecord, NonceState, OneTimeNonceState,
    PlatformHandle, PriorKernelDisposition, ResourceGeneration, ServiceProcessRecord,
    ServiceProcessState, append_reconciled, fresh_kernel_activation_nonce,
    nonce_after_activation_failure, operation, prove_candidate_owner_held, record_fence,
    sha256_json,
};

// F-LOG-HOST-3 (#978) Kernel-activation observation helpers.
//
// Through the #889 facade only
// (`super::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`super::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open). No terminal is owned here: the single terminal for a
// failed activation stays with the outermost #891 contour (e.g.
// `host-start-failed` / `host-resume-pending-failed` in `lib.rs`); nonce,
// handshake, auth, activation, and readiness correlate by stage order only.
// This coordinates the "one terminal across nesting" rule with #891.
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static literals only — never nonces,
// digests, operation ids, pipe identities, evidence refs, or arbitrary error
// text — so bounding limits size, not sensitivity (I15.4). Sink outcome never
// alters result/order/status/cleanup. There is no mutable global dedup cache.
#[cfg(windows)]
fn kernel_activation_note_event_log_unavailable() {
    let _ = super::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn kernel_activation_observe(detail: &str) {
    kernel_activation_note_event_log_unavailable();
    super::host_diagnostics::observe_entrypoint_with_detail(
        super::host_diagnostics::EntrypointStage::Startup,
        detail,
    );
}

#[cfg(windows)]
pub(super) struct DurableKernelActivationDriver<'a, B: JournalBackend> {
    journal: &'a HostStateJournalService<B>,
    current: KernelRecord,
    issued_permit: Option<KernelActivationPermit>,
    /// I14.16 step 5: the retained handoff boundary of the retired contour.
    /// `None` means no prior Kernel existed. A replacement contour cannot
    /// commit prior disposition without one, so the lock-release proof and
    /// the durable record cannot be separated.
    handoff: Option<KernelHandoffReceipt>,
}

#[cfg(windows)]
impl<'a, B: JournalBackend> DurableKernelActivationDriver<'a, B> {
    pub(super) fn resume(journal: &'a HostStateJournalService<B>, current: KernelRecord) -> Self {
        // WORK_UNIT_CASE: 978/10 — resume correlates by stage order only;
        // no terminal here, the outermost #891 contour owns it.
        kernel_activation_observe("host.kernel-activation resume requested");
        Self {
            journal,
            current,
            issued_permit: None,
            handoff: None,
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the durable candidate record keeps every authority and mechanics binding explicit"
    )]
    pub(super) fn bind_candidate(
        journal: &'a HostStateJournalService<B>,
        host: &HostInstallationEpoch,
        activation_id: &PlatformHandle,
        activation_generation: &EpochTransition,
        approved_artifact_hash: PlatformHandle,
        candidate_pipe_identity: PlatformHandle,
        candidate_job_binding: KernelJobBinding,
        prior_kernel_disposition: PriorKernelDisposition,
        kernel_generation: EpochTransition,
        process: ServiceProcessRecord,
    ) -> Result<Self, HostError> {
        // WORK_UNIT_CASE: 978/7 — candidate bind requested; handshake/auth
        // material is distinct from nonce/activation, no secrets observed.
        kernel_activation_observe("host.kernel-activation bind requested");
        let current = KernelRecord {
            fence: record_fence(host, activation_id, activation_generation),
            operation: operation("kernel-candidate-shadow")?,
            activation_identity: activation_id.clone(),
            approved_artifact_hash,
            active_pipe_identity: None,
            candidate_pipe_identity: Some(candidate_pipe_identity),
            candidate_job_binding: Some(candidate_job_binding),
            prior_kernel_disposition,
            kernel_generation,
            one_time_nonce: OneTimeNonceState::unissued(),
            state: KernelActivationState::ShadowNoAuthority,
            process: Some(process),
            readiness_evidence: Vec::new(),
            disposition_evidence: vec![
                PlatformHandle::new("candidate-process-job-bound")
                    .map_err(|error| HostError::Platform(error.to_string()))?,
            ],
        };
        append_reconciled(journal, HostStateRecord::Kernel(current.clone()))?;
        // WORK_UNIT_CASE: 978/7 — candidate observed; still distinct from
        // nonce issuance and activation below.
        kernel_activation_observe("host.kernel-activation candidate observed");
        Ok(Self {
            journal,
            current,
            issued_permit: None,
            handoff: None,
        })
    }

    fn transition(
        &mut self,
        state: KernelActivationState,
        label: &str,
        mutate: impl FnOnce(&mut KernelRecord) -> Result<(), HostError>,
    ) -> Result<AppendReceipt, HostError> {
        let mut next = self.current.clone();
        next.operation = operation(label)?;
        next.state = state;
        mutate(&mut next)?;
        let receipt = append_reconciled(self.journal, HostStateRecord::Kernel(next.clone()))?;
        self.current = next;
        Ok(receipt)
    }

    /// Records the I14.16 step-5 handoff boundary for the retired contour.
    ///
    /// The receipt is compared by content against the prior disposition this
    /// activation already carries, so a receipt describing a different
    /// retired contour cannot advance this one, and `None` is accepted only
    /// when there was genuinely no prior Kernel. The receipt authorizes
    /// nothing yet: the exclusive owner object is probed in
    /// [`Self::prior_disposition_committed`], which is the only step that may
    /// unblock nonce issuance.
    pub(super) fn handoff_prepared(
        &mut self,
        handoff: Option<&KernelHandoffReceipt>,
    ) -> Result<(), HostError> {
        let disposition = &self.current.prior_kernel_disposition;
        match handoff {
            Some(receipt) => {
                if !receipt.matches_disposition(disposition) {
                    return Err(HostError::ProcessContour(
                        "Kernel handoff receipt does not match this activation's prior contour"
                            .to_owned(),
                    ));
                }
            }
            None => {
                if !matches!(disposition, PriorKernelDisposition::NoPriorKernel) {
                    return Err(HostError::ProcessContour(
                        "Kernel handoff requires a receipt for the recorded prior contour"
                            .to_owned(),
                    ));
                }
            }
        }
        let evidence = match handoff {
            Some(receipt) => Some(receipt.evidence_ref()?),
            None => None,
        };
        self.handoff = handoff.cloned();
        self.transition(
            KernelActivationState::HandoffPrepared,
            "kernel-handoff-prepared",
            |next| {
                if let Some(evidence) = evidence {
                    next.disposition_evidence.push(evidence);
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    /// Commits the retired contour's disposition only after Host has proven,
    /// on the live operating-system object, that the retired Kernel released
    /// its exclusive ownership.
    ///
    /// Process termination alone is not this proof: `journal_append::
    /// terminated_prior_kernel` proves the Job is empty and the root is
    /// reaped, while [`KernelHandoffReceipt::prove_released`] proves no
    /// process still owns that contour. Nonce issuance is already gated on
    /// `OldTerminated`, so an unproven release can never reach it.
    pub(super) fn prior_disposition_committed(&mut self) -> Result<(), HostError> {
        if let Some(handoff) = self.handoff.as_ref() {
            handoff.prove_released()?;
        } else if !matches!(
            self.current.prior_kernel_disposition,
            PriorKernelDisposition::NoPriorKernel
        ) {
            return Err(HostError::ProcessContour(
                "prior disposition commit requires the recorded Kernel handoff receipt".to_owned(),
            ));
        }
        self.transition(
            KernelActivationState::OldTerminated,
            "kernel-prior-disposition",
            |_| Ok(()),
        )?;
        Ok(())
    }

    pub(super) fn issue_nonce(
        &mut self,
        candidate: &HostKernelCandidateBinding,
        generation: ResourceGeneration,
    ) -> Result<KernelActivationPermit, HostError> {
        // WORK_UNIT_CASE: 978/7 — nonce requested; the nonce value itself is
        // never observed, only this static literal (no secrets).
        kernel_activation_observe("host.kernel-activation nonce requested");
        if self.current.state != KernelActivationState::OldTerminated {
            return Err(HostError::ProcessContour(
                "activation nonce cannot be issued before prior disposition commit".to_owned(),
            ));
        }
        let nonce = fresh_kernel_activation_nonce()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let receipt = self.transition(
            KernelActivationState::NonceIssued,
            "kernel-nonce-issued",
            |next| {
                next.one_time_nonce = OneTimeNonceState::issued(nonce.clone());
                Ok(())
            },
        )?;
        let prior_kernel_disposition_digest = sha256_json(&self.current.prior_kernel_disposition)?;
        let permit = KernelActivationPermit {
            operation_id: self.current.operation.operation_id.clone(),
            candidate_binding_digest: candidate
                .compute_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            prior_kernel_disposition_digest,
            journal_transaction_id: receipt.transaction_id().clone(),
            journal_sequence: receipt.sequence(),
            generation,
            authority_epoch: candidate.kernel_epoch.clone(),
            activation_nonce: nonce,
        };
        permit
            .validate(candidate, generation)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        self.issued_permit = Some(permit.clone());
        // WORK_UNIT_CASE: 978/7 — nonce issued distinctly from handshake/auth
        // and activation; exact permit propagates unchanged.
        kernel_activation_observe("host.kernel-activation nonce issued");
        Ok(permit)
    }

    pub(super) fn activating(&mut self) -> Result<(), HostError> {
        // WORK_UNIT_CASE: 978/7 — activating requested; forbidden before the
        // committed NonceIssued receipt, distinct from nonce issuance.
        kernel_activation_observe("host.kernel-activation activating requested");
        if self.issued_permit.is_none() {
            return Err(HostError::ProcessContour(
                "Activate is forbidden before a committed NonceIssued receipt".to_owned(),
            ));
        }
        self.transition(
            KernelActivationState::Activating,
            "kernel-activating",
            |_| Ok(()),
        )?;
        Ok(())
    }

    pub(super) fn active(
        &mut self,
        candidate: &HostKernelCandidateBinding,
        activation_receipt: &KernelActivationReceipt,
        ready: &KernelReadyReceipt,
    ) -> Result<(), HostError> {
        // WORK_UNIT_CASE: 978/8 — readiness requested; positive activation
        // requires actual owner evidence (permit + receipts), never liveness
        // alone.
        kernel_activation_observe("host.kernel-activation readiness requested");
        // I14.16 step 7/8: the candidate must hold exclusive ownership of its
        // own contour before Host publishes it. This runs before the permit,
        // receipt and nonce checks so a candidate that never took the owner
        // object is refused here, not after the stable pipe is committed.
        prove_candidate_owner_held(candidate)?;
        let permit = self.issued_permit.as_ref().ok_or_else(|| {
            HostError::ProcessContour("active Kernel is missing its issued permit".to_owned())
        })?;
        activation_receipt
            .validate(permit)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        ready
            .validate(candidate, activation_receipt)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        self.transition(KernelActivationState::Active, "kernel-active", |next| {
            next.active_pipe_identity = next.candidate_pipe_identity.clone();
            next.one_time_nonce = next.one_time_nonce.consume()?;
            let process = next.process.as_mut().ok_or_else(|| {
                HostError::ProcessContour("active Kernel process binding is absent".to_owned())
            })?;
            process.state = ServiceProcessState::Ready;
            process.health = ready.health;
            next.readiness_evidence.clone_from(&ready.evidence_refs);
            next.readiness_evidence.push(
                PlatformHandle::new(format!(
                    "kernel-activation-receipt:{}",
                    activation_receipt.operation_id.as_str()
                ))
                .map_err(|error| HostError::Platform(error.to_string()))?,
            );
            Ok(())
        })?;
        // WORK_UNIT_CASE: 978/7 — activation observed distinctly from nonce/
        // handshake/auth; WORK_UNIT_CASE: 978/8 — readiness observed only on
        // exact owner evidence above, exact errors propagate unchanged.
        kernel_activation_observe("host.kernel-activation activation observed");
        kernel_activation_observe("host.kernel-activation readiness observed");
        Ok(())
    }

    pub(super) fn fail(&mut self, evidence: &str) -> Result<(), HostError> {
        // WORK_UNIT_CASE: 978/10 — failure observed without owning a terminal;
        // the outermost #891 contour emits the single terminal. The evidence
        // label stays owner-supplied; only this static literal is observed.
        kernel_activation_observe("host.kernel-activation fail observed");
        if self.current.state == KernelActivationState::Failed {
            return Ok(());
        }
        let evidence = PlatformHandle::new(evidence)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        self.transition(
            KernelActivationState::Failed,
            "kernel-activation-failed",
            |next| {
                next.one_time_nonce = nonce_after_activation_failure(&next.one_time_nonce)?;
                if next.one_time_nonce.state() != NonceState::Consumed {
                    next.active_pipe_identity = None;
                }
                next.readiness_evidence.clear();
                next.disposition_evidence.push(evidence);
                if let Some(process) = next.process.as_mut() {
                    process.state = ServiceProcessState::Failed;
                    process.health.liveness = HealthDimension::Unknown;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}
