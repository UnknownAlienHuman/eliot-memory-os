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
// `host-start-failed` / `host-resume-pending-failed` in `lib.rs`). This
// coordinates the "one terminal across nesting" rule with #891.
//
// Correlation contract (audit 5910159678 DEFECT 5): this driver holds the
// exact activation id and generation, the owner-minted operation identity, the
// journal transaction and sequence of the append it just committed, the
// candidate binding, the process-start identity and authority epoch, and the
// activation receipt identity. Every phase record below therefore projects
// those already-held identities through the facade's existing bounded-detail
// projection, so two interleaved or retried activation contours produce
// distinguishable records instead of identical static strings. Nothing is
// inferred from stage order and nothing is borrowed from a neighbouring phase:
// an identity this driver does not hold at the emission site is spelled
// `unavailable` rather than guessed (I07.20).
//
// Non-secret projection only (I15.4): the activation nonce value, its digest,
// the credential material, the ready-receipt evidence handles, the failure
// evidence label, and arbitrary error text never reach a record. Every
// variable-width identity enters as a SHA-256 digest over the owner value,
// never as raw text — the candidate pipe identity and Job binding are a pipe
// and an image path in the owner's hands, and the operation, transaction and
// activation handles are long composites. A digest failure is reported as
// `unavailable`, never as a fabricated or partial identity, and never changes
// the caller's result. Each digest is a fixed 64 hex characters, so the
// composed record fits the facade's own `MAX_DIAGNOSTIC_DETAIL_BYTES` bound
// without its truncation silently dropping a tail identity: a record that
// cannot carry every field it names would be a vacuous correlation.
//
// The two generation sequences and the authority epoch are already bounded
// integers and are recorded as themselves, because a sequence number and an
// epoch are exactly what the owner fences on and what makes a forked or
// rolled-back lineage visible in the record.
//
// Sink outcome never alters result/order/status/cleanup, and there is no
// mutable global dedup cache.
//
// Readiness remains owned by exactly one path: `active`, after the permit, the
// activation receipt, and the ready receipt have all validated. No helper here
// emits a second readiness claim.
#[cfg(windows)]
const KERNEL_ACTIVATION_IDENTITY_UNAVAILABLE: &str = "unavailable";

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

/// Projects one already-held, non-secret owner identity as a fixed-width
/// non-secret digest, bounded by the facade's own short-field bound.
///
/// This is the convention the activation boundary already uses to carry
/// identity across owners (`KernelActivationPermit::candidate_binding_digest`),
/// so a record names the exact value without echoing it. A digest failure is
/// reported as explicitly unavailable rather than as a fabricated or partial
/// identity, and never changes the caller's result.
#[cfg(windows)]
fn kernel_activation_digest(value: &impl serde::Serialize) -> String {
    sha256_json(value).map_or_else(
        |_| KERNEL_ACTIVATION_IDENTITY_UNAVAILABLE.to_owned(),
        |digest| super::host_diagnostics::bound_field(&digest).text().to_owned(),
    )
}

/// Projects one activation phase record: a static phase literal plus every
/// already-held, bounded, non-secret identity of this activation.
///
/// The phase literal is the only static part. Each remaining component is an
/// owner value passed in at the emission site, so a record names the exact
/// activation, operation, journal append, candidate binding, process
/// incarnation, and authority epoch it belongs to. Components the emission site
/// does not hold are passed as `None` and render as unavailable; nothing is
/// probed, looked up, or synthesized here.
#[cfg(windows)]
#[allow(
    clippy::too_many_arguments,
    reason = "the projection names every activation identity the owner already holds, so none can be silently dropped"
)]
fn kernel_activation_detail(
    phase: &str,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
    operation_id: Option<&PlatformHandle>,
    kernel_generation: &EpochTransition,
    candidate_pipe_identity: Option<&PlatformHandle>,
    candidate_job_binding: Option<&KernelJobBinding>,
    process: Option<&ServiceProcessRecord>,
    approved_artifact_hash: &PlatformHandle,
    receipt: Option<&AppendReceipt>,
    receipt_operation: Option<&PlatformHandle>,
) -> String {
    let operation = operation_id.map_or_else(
        || KERNEL_ACTIVATION_IDENTITY_UNAVAILABLE.to_owned(),
        |id| kernel_activation_digest(&id.as_str()),
    );
    // The candidate binding is projected only when this driver holds both
    // halves; one half alone would name a contour it cannot fully identify.
    let candidate_binding = match (candidate_pipe_identity, candidate_job_binding) {
        (Some(pipe), Some(binding)) => kernel_activation_digest(&(pipe, binding)),
        _ => KERNEL_ACTIVATION_IDENTITY_UNAVAILABLE.to_owned(),
    };
    let artifact = kernel_activation_digest(&approved_artifact_hash.as_str());
    let (process_identity, authority_epoch) = process.map_or_else(
        || {
            (
                KERNEL_ACTIVATION_IDENTITY_UNAVAILABLE.to_owned(),
                KERNEL_ACTIVATION_IDENTITY_UNAVAILABLE.to_owned(),
            )
        },
        |process| {
            (
                kernel_activation_digest(&process.process_id.as_str()),
                process.authority_epoch.value().to_string(),
            )
        },
    );
    let (transaction, sequence) = receipt.map_or_else(
        || {
            (
                KERNEL_ACTIVATION_IDENTITY_UNAVAILABLE.to_owned(),
                KERNEL_ACTIVATION_IDENTITY_UNAVAILABLE.to_owned(),
            )
        },
        |receipt| {
            (
                kernel_activation_digest(&receipt.transaction_id().as_str()),
                receipt.sequence().to_string(),
            )
        },
    );
    let receipt_operation = receipt_operation.map_or_else(
        || KERNEL_ACTIVATION_IDENTITY_UNAVAILABLE.to_owned(),
        |id| kernel_activation_digest(&id.as_str()),
    );
    format!(
        "{phase} act={} agen={} kgen={} op={} tx={} seq={} candidate={} artifact={} process={} authority_epoch={} receipt_op={}",
        kernel_activation_digest(&activation_id.as_str()),
        activation_generation.current.sequence.get(),
        kernel_generation.current.sequence.get(),
        operation,
        transaction,
        sequence,
        candidate_binding,
        artifact,
        process_identity,
        authority_epoch,
        receipt_operation,
    )
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
        // WORK_UNIT_CASE: 978/10 — no terminal here, the outermost #891 contour
        // owns it. The resumed record already carries this activation's fence,
        // operation identity, candidate binding, process incarnation, and
        // authority epoch, so the record is bound to them instead of
        // correlating by stage order alone (audit 5910159678 DEFECT 5). No
        // journal receipt exists yet at resume, so transaction and sequence
        // stay explicitly unavailable.
        kernel_activation_observe(&kernel_activation_detail(
            "host.kernel-activation resume requested",
            &current.activation_identity,
            &current.fence.activation_generation,
            Some(&current.operation.operation_id),
            &current.kernel_generation,
            current.candidate_pipe_identity.as_ref(),
            current.candidate_job_binding.as_ref(),
            current.process.as_ref(),
            &current.approved_artifact_hash,
            None,
            None,
        ));
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
        // Every identity projected here is already held by this call: the exact
        // activation id and generation, the candidate pipe identity and Job
        // binding, the Kernel generation, the process-start record with its
        // authority epoch, and the approved artifact reference. The record is
        // therefore attributable to this activation contour rather than to a
        // stage position (audit 5910159678 DEFECT 5). No journal append has
        // committed yet and no operation identity has been minted yet, so
        // transaction, sequence, and operation stay explicitly unavailable
        // rather than being filled from a later phase.
        kernel_activation_observe(&kernel_activation_detail(
            "host.kernel-activation bind requested",
            activation_id,
            activation_generation,
            None,
            &kernel_generation,
            Some(&candidate_pipe_identity),
            Some(&candidate_job_binding),
            Some(&process),
            &approved_artifact_hash,
            None,
            None,
        ));
        // I14.16 step 7 (issue #1953 W6): the candidate generation must be
        // the strict direct child of the retired contour's generation. The
        // journal reducer pins this on first bind, but a same-activation
        // rebind consults only the disposition binding, so the driver
        // refuses a forked lineage here, before any nonce can be issued for
        // it. Rollback is a newer activation, never a reused generation.
        if let PriorKernelDisposition::Terminated(source) = &prior_kernel_disposition
            && !kernel_generation.advances(&source.generation.current)
        {
            return Err(HostError::ProcessContour(
                "candidate Kernel generation must directly advance the terminated prior contour"
                    .to_owned(),
            ));
        }
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
        let receipt = append_reconciled(journal, HostStateRecord::Kernel(current.clone()))?;
        // WORK_UNIT_CASE: 978/7 — candidate observed; still distinct from
        // nonce issuance and activation below. This record additionally carries
        // the committed journal transaction and sequence of this bind and the
        // minted `kernel-candidate-shadow` operation identity, so a retried or
        // concurrent bind of the same activation is distinguishable by the exact
        // append that recorded it (audit 5910159678 DEFECT 5).
        kernel_activation_observe(&kernel_activation_detail(
            "host.kernel-activation candidate observed",
            &current.activation_identity,
            &current.fence.activation_generation,
            Some(&current.operation.operation_id),
            &current.kernel_generation,
            current.candidate_pipe_identity.as_ref(),
            current.candidate_job_binding.as_ref(),
            current.process.as_ref(),
            &current.approved_artifact_hash,
            Some(&receipt),
            None,
        ));
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
                if let Some(evidence) = evidence.filter(|e| !next.disposition_evidence.contains(e))
                {
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
    /// process still owns that contour. A resumed driver rejoins the handoff
    /// boundary its own activation record already retained before proving
    /// release, so an interrupted handoff continues under the original Host
    /// activation instead of stalling or accepting a replacement receipt;
    /// the release proof still re-probes the live object, and recovery never
    /// substitutes for it. Nonce issuance is already gated on
    /// `OldTerminated`, so an unproven release can never reach it.
    pub(super) fn prior_disposition_committed(&mut self) -> Result<(), HostError> {
        if self.handoff.is_none() {
            self.handoff = KernelHandoffReceipt::recover_retained(&self.current)?;
        }
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
        // never observed. This record projects only identities the current
        // durable record already holds, so a nonce request is attributable to
        // its activation, operation, generation, candidate binding, and process
        // incarnation without ever touching the one-use authority (I15.4;
        // audit 5910159678 DEFECT 5). The `NonceIssued` record has not been
        // appended yet, so its own transaction and sequence stay explicitly
        // unavailable rather than being borrowed from the append below.
        kernel_activation_observe(&kernel_activation_detail(
            "host.kernel-activation nonce requested",
            &self.current.activation_identity,
            &self.current.fence.activation_generation,
            Some(&self.current.operation.operation_id),
            &self.current.kernel_generation,
            self.current.candidate_pipe_identity.as_ref(),
            self.current.candidate_job_binding.as_ref(),
            self.current.process.as_ref(),
            &self.current.approved_artifact_hash,
            None,
            None,
        ));
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
        // and activation; exact permit propagates unchanged. This record
        // carries the committed `NonceIssued` journal transaction and sequence
        // plus the minted operation identity, so two activations that each reach
        // a nonce are distinguishable by the exact append that issued it. The
        // nonce value and its digest are never projected (I15.4).
        kernel_activation_observe(&kernel_activation_detail(
            "host.kernel-activation nonce issued",
            &self.current.activation_identity,
            &self.current.fence.activation_generation,
            Some(&self.current.operation.operation_id),
            &self.current.kernel_generation,
            self.current.candidate_pipe_identity.as_ref(),
            self.current.candidate_job_binding.as_ref(),
            self.current.process.as_ref(),
            &self.current.approved_artifact_hash,
            Some(&receipt),
            Some(&permit.operation_id),
        ));
        Ok(permit)
    }

    pub(super) fn activating(&mut self) -> Result<(), HostError> {
        // WORK_UNIT_CASE: 978/7 — activating requested; forbidden before the
        // committed NonceIssued receipt, distinct from nonce issuance. The
        // record is bound to the exact activation, operation, generation,
        // candidate binding, and process incarnation this contour already
        // holds, so it cannot be confused with another activation's Activate
        // phase (audit 5910159678 DEFECT 5). No append for this phase has
        // committed yet, so transaction and sequence stay unavailable.
        kernel_activation_observe(&kernel_activation_detail(
            "host.kernel-activation activating requested",
            &self.current.activation_identity,
            &self.current.fence.activation_generation,
            Some(&self.current.operation.operation_id),
            &self.current.kernel_generation,
            self.current.candidate_pipe_identity.as_ref(),
            self.current.candidate_job_binding.as_ref(),
            self.current.process.as_ref(),
            &self.current.approved_artifact_hash,
            None,
            None,
        ));
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
        // alone. This is a request-phase record only: it asserts no readiness
        // and carries no evidence beyond the identities already in hand. It is
        // bound to the exact activation, operation, generation, candidate
        // binding, and process incarnation so it is attributable to one contour
        // (audit 5910159678 DEFECT 5). No append for this phase has committed
        // yet, so transaction and sequence stay unavailable.
        kernel_activation_observe(&kernel_activation_detail(
            "host.kernel-activation readiness requested",
            &self.current.activation_identity,
            &self.current.fence.activation_generation,
            Some(&self.current.operation.operation_id),
            &self.current.kernel_generation,
            self.current.candidate_pipe_identity.as_ref(),
            self.current.candidate_job_binding.as_ref(),
            self.current.process.as_ref(),
            &self.current.approved_artifact_hash,
            None,
            None,
        ));
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
        let receipt = self.transition(KernelActivationState::Active, "kernel-active", |next| {
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
        // exact owner evidence above, exact errors propagate unchanged. These
        // two records are the sole readiness emitters for Kernel activation,
        // and each projects the committed `Active` append's transaction and
        // sequence, the activation operation identity, and the exact
        // activation-receipt operation id that the validated evidence carries,
        // so a positive readiness claim is attributable to the one owner
        // evidence that authorized it (audit 5910159678 DEFECT 5). The
        // activation nonce, its digest, and the ready-receipt evidence handles
        // are never projected (I15.4).
        kernel_activation_observe(&kernel_activation_detail(
            "host.kernel-activation activation observed",
            &self.current.activation_identity,
            &self.current.fence.activation_generation,
            Some(&self.current.operation.operation_id),
            &self.current.kernel_generation,
            self.current.candidate_pipe_identity.as_ref(),
            self.current.candidate_job_binding.as_ref(),
            self.current.process.as_ref(),
            &self.current.approved_artifact_hash,
            Some(&receipt),
            Some(&activation_receipt.operation_id),
        ));
        kernel_activation_observe(&kernel_activation_detail(
            "host.kernel-activation readiness observed",
            &self.current.activation_identity,
            &self.current.fence.activation_generation,
            Some(&self.current.operation.operation_id),
            &self.current.kernel_generation,
            self.current.candidate_pipe_identity.as_ref(),
            self.current.candidate_job_binding.as_ref(),
            self.current.process.as_ref(),
            &self.current.approved_artifact_hash,
            Some(&receipt),
            Some(&activation_receipt.operation_id),
        ));
        Ok(())
    }

    pub(super) fn fail(&mut self, evidence: &str) -> Result<(), HostError> {
        // WORK_UNIT_CASE: 978/10 — failure observed without owning a terminal;
        // the outermost #891 contour emits the single terminal. The record is
        // bound to the exact activation, operation, generation, candidate
        // binding, and process incarnation this contour already holds, so the
        // failure phase of one activation is distinguishable from another's
        // (audit 5910159678 DEFECT 5). The owner-supplied failure evidence
        // label and any error text stay with their owner and never enter a
        // record (I15.4, I07.20); the `Failed` append that follows carries the
        // evidence in the journal, not here. No `Failed` append has committed
        // at this emission site, so transaction and sequence stay unavailable.
        kernel_activation_observe(&kernel_activation_detail(
            "host.kernel-activation fail observed",
            &self.current.activation_identity,
            &self.current.fence.activation_generation,
            Some(&self.current.operation.operation_id),
            &self.current.kernel_generation,
            self.current.candidate_pipe_identity.as_ref(),
            self.current.candidate_job_binding.as_ref(),
            self.current.process.as_ref(),
            &self.current.approved_artifact_hash,
            None,
            None,
        ));
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
