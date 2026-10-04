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
use crate::host_job_launch::LaunchPhaseCorrelation;

// F-LOG-HOST-3 (#978) Kernel-activation observation helpers.
//
// Through the #889 facade only
// (`super::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`super::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open). No terminal is owned here: the single terminal for a
// failed activation stays with the outermost #891 contour in `lib.rs`, whose armed
// boundary on the STARTUP launch path is `BOUNDARY_OPEN_TERMINAL`, a cutover-path
// launch's is `BOUNDARY_BACKUP_CUTOVER_TERMINAL`, and a phase-B resume by `BOUNDARY_RESUME_PENDING_TERMINAL` instead. This
// coordinates the "one terminal across nesting" rule with #891.
//
// Bounded identities, not stage order alone (audit 5910159678 defects 3 and 5):
// a call site passes a static phase token plus a
// `LaunchPhaseCorrelation` built only from identities this driver already
// holds — the KernelRecord operation identity, the approved artifact hash
// handle, the installation handle, and the activation identity the record
// fence carries. `fence` therefore means exactly one thing in this file: the
// activation/state-fence identity of the record the phase belongs to, on every
// call site, and no other identity is ever bound into it. `process_start` is
// the Host-observed Kernel Job root process start identity — the root pid
// together with the handle-observed creation time — projected on every call
// site that retains one, from the retained `candidate_job_binding` alone,
// never from a Kernel-authored process handle and never from a bare reusable
// pid; a call site whose record retained no Job binding renders the
// renderer's explicit absence marker instead. `generation` carries the
// approved runtime generation where a permit, receipt or request holds one, and
// the record's activation-generation sequence otherwise. Nothing is re-derived,
// re-read, re-verified or probed to obtain a field: an absent identity renders
// as the renderer's own explicit absence marker instead of being invented.
//
// Secrets and payloads never cross this boundary. The one-use permit secret is
// never bound or observed in any form, and neither is the nonce state value,
// receipt or health payload text, evidence reference handles, pipe identities,
// credential material, or arbitrary error text — including the owner-supplied
// failure evidence label, which stays owner-supplied. A process start identity
// is rendered as the owner's own pid/start pair, so a record names the contour
// that produced it and the process incarnation it concerns without naming a
// payload. The Kernel authority epoch reaches no slot on any call site here: no
// key in the frozen correlation vocabulary carries it, and binding it into
// `fence` is exactly what made that key mean two identities. Bounding limits
// size, not sensitivity (I15.4). Sink outcome never alters
// result/order/status/cleanup.
// There is no mutable global dedup cache.
//
// The final Kernel acceptance claim stays owned here: only this file's
// owner-evidence path may make it, and only after the exclusive owner probe,
// the permit, the activation receipt and the ready receipt are validated and
// the `Active` transition is committed.
#[cfg(windows)]
fn kernel_activation_note_event_log_unavailable() {
    let _ = super::windows_event_log::event_log_sink_status();
}

/// Renders the Kernel Job root process start identity in the owner's own
/// `pid`/`start` shape, so a record distinguishes this process incarnation from
/// a reusable PID.
#[cfg(windows)]
fn kernel_process_start_identity(root_pid: u32, root_start_time_100ns: u64) -> String {
    format!("pid:{root_pid}:start:{root_start_time_100ns}")
}

#[cfg(windows)]
fn kernel_activation_observe(phase: &str, correlation: &LaunchPhaseCorrelation<'_>) {
    kernel_activation_note_event_log_unavailable();
    let detail = correlation.render(phase);
    super::host_diagnostics::observe_entrypoint_with_detail(
        super::host_diagnostics::EntrypointStage::Startup,
        &detail,
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
        // WORK_UNIT_CASE: 978/10 — resume observes the retained record's own
        // identities, not stage order alone; no terminal here, the outermost
        // #891 contour owns it.
        let mut correlation = LaunchPhaseCorrelation::NONE
            .with_installation(current.fence.host.installation.as_str())
            .with_generation(current.fence.activation_generation.current.sequence.get())
            .with_operation(current.operation.operation_id.as_str())
            .with_artifact(current.approved_artifact_hash.as_str())
            .with_fence(current.fence.activation_id.as_str());
        // The retained Job binding is already held by the resumed record, so the
        // process start identity is in hand: projected exactly as `active`
        // projects it, read from the record and never re-derived or probed.
        let process_start = current.candidate_job_binding.as_ref().map(|job_binding| {
            kernel_process_start_identity(job_binding.root_pid, job_binding.root_start_time_100ns)
        });
        if let Some(process_start) = process_start.as_deref() {
            correlation = correlation.with_process_start(process_start);
        }
        kernel_activation_observe("host.kernel-activation resume requested", &correlation);
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
        // material is distinct from nonce/activation, no secrets observed. The
        // exact Job root process start identity and the activation fence are
        // already in hand as parameters, so both are named.
        let process_start = kernel_process_start_identity(
            candidate_job_binding.root_pid,
            candidate_job_binding.root_start_time_100ns,
        );
        let correlation = LaunchPhaseCorrelation::NONE
            .with_installation(host.installation.as_str())
            .with_generation(activation_generation.current.sequence.get())
            .with_artifact(approved_artifact_hash.as_str())
            .with_process_start(&process_start)
            .with_fence(activation_id.as_str());
        kernel_activation_observe("host.kernel-activation bind requested", &correlation);
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
        append_reconciled(journal, HostStateRecord::Kernel(current.clone()))?;
        // WORK_UNIT_CASE: 978/7 — candidate observed; still distinct from
        // nonce issuance and activation below. The committed record now carries
        // the operation identity this append established, and the same Job root
        // process start identity observed at bind time.
        let correlation = LaunchPhaseCorrelation::NONE
            .with_installation(current.fence.host.installation.as_str())
            .with_generation(current.fence.activation_generation.current.sequence.get())
            .with_operation(current.operation.operation_id.as_str())
            .with_artifact(current.approved_artifact_hash.as_str())
            .with_process_start(&process_start)
            .with_fence(current.fence.activation_id.as_str());
        kernel_activation_observe("host.kernel-activation candidate observed", &correlation);
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
        // WORK_UNIT_CASE: 978/7 — nonce requested; the one-use secret is
        // never observed. The approved runtime generation the request carries,
        // the committed record's activation fence and its retained Job root
        // process start identity are named; the authority epoch this permit
        // will bind is named by no slot, because `fence` means the activation
        // identity alone.
        let mut correlation = LaunchPhaseCorrelation::NONE
            .with_installation(self.current.fence.host.installation.as_str())
            .with_generation(generation.value())
            .with_operation(self.current.operation.operation_id.as_str())
            .with_artifact(self.current.approved_artifact_hash.as_str())
            .with_fence(self.current.fence.activation_id.as_str());
        // The committed record holds this contour's Job binding, so the process
        // start identity is in hand: projected exactly as `active` projects it.
        let process_start = self
            .current
            .candidate_job_binding
            .as_ref()
            .map(|job_binding| {
                kernel_process_start_identity(
                    job_binding.root_pid,
                    job_binding.root_start_time_100ns,
                )
            });
        if let Some(process_start) = process_start.as_deref() {
            correlation = correlation.with_process_start(process_start);
        }
        kernel_activation_observe("host.kernel-activation nonce requested", &correlation);
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
        // and activation; exact permit propagates unchanged. The issued permit's
        // operation identity and journal generation are named with the committed
        // record's own activation fence and the same retained Job root process
        // start identity the request named. The permit's authority epoch, its
        // one-use secret and the committed journal transaction identity stay
        // unobserved because no bound field carries them.
        let mut correlation = LaunchPhaseCorrelation::NONE
            .with_installation(self.current.fence.host.installation.as_str())
            .with_generation(permit.generation.value())
            .with_operation(permit.operation_id.as_str())
            .with_artifact(self.current.approved_artifact_hash.as_str())
            .with_fence(self.current.fence.activation_id.as_str());
        // The committed record holds this contour's Job binding, so the process
        // start identity is in hand: projected exactly as `active` projects it.
        let process_start = self
            .current
            .candidate_job_binding
            .as_ref()
            .map(|job_binding| {
                kernel_process_start_identity(
                    job_binding.root_pid,
                    job_binding.root_start_time_100ns,
                )
            });
        if let Some(process_start) = process_start.as_deref() {
            correlation = correlation.with_process_start(process_start);
        }
        kernel_activation_observe("host.kernel-activation nonce issued", &correlation);
        Ok(permit)
    }

    pub(super) fn activating(&mut self) -> Result<(), HostError> {
        // WORK_UNIT_CASE: 978/7 — activating requested; forbidden before the
        // committed NonceIssued receipt, distinct from nonce issuance. The
        // record names the activation fence its own committed record carries,
        // identically whether or not a permit already exists, so `fence` keeps
        // one meaning and no authority epoch displaces it. It also names that
        // record's retained Job root process start identity, which no permit
        // state changes.
        let mut correlation = LaunchPhaseCorrelation::NONE
            .with_installation(self.current.fence.host.installation.as_str())
            .with_generation(
                self.current
                    .fence
                    .activation_generation
                    .current
                    .sequence
                    .get(),
            )
            .with_operation(self.current.operation.operation_id.as_str())
            .with_artifact(self.current.approved_artifact_hash.as_str())
            .with_fence(self.current.fence.activation_id.as_str());
        // The committed record holds this contour's Job binding, so the process
        // start identity is in hand: projected exactly as `active` projects it.
        let process_start = self
            .current
            .candidate_job_binding
            .as_ref()
            .map(|job_binding| {
                kernel_process_start_identity(
                    job_binding.root_pid,
                    job_binding.root_start_time_100ns,
                )
            });
        if let Some(process_start) = process_start.as_deref() {
            correlation = correlation.with_process_start(process_start);
        }
        kernel_activation_observe("host.kernel-activation activating requested", &correlation);
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

    /// The owner-evidence path of `DurableKernelActivationDriver::active`.
    ///
    /// This is the only place that may claim Kernel readiness. The
    /// `readiness requested` record precedes every validation, so it names no
    /// identity at all.
    ///
    /// Inside this function the issued permit is required to be *present* —
    /// `self.issued_permit` holding `None` is refused — and
    /// `activation_receipt.validate(permit)` only proves the receipt equals
    /// `KernelActivationReceipt::issue(permit)` for that same permit. The
    /// permit's own validation against the candidate, including the authority
    /// epoch comparison, is not repeated here: it already ran in
    /// [`Self::issue_nonce`], which is the only path that can refuse a permit,
    /// so a permit reaching this function has been validated there.
    ///
    /// What this function does validate is the exclusive owner probe and the
    /// ready receipt. The `Active` transition is committed only after all of
    /// that, and the `activation observed` and `readiness observed` records are
    /// emitted after the commit, composed from the committed record itself. A
    /// running process, a returned launch child or an IPC acknowledgement never
    /// produces this claim.
    pub(super) fn active(
        &mut self,
        candidate: &HostKernelCandidateBinding,
        activation_receipt: &KernelActivationReceipt,
        ready: &KernelReadyReceipt,
    ) -> Result<(), HostError> {
        // WORK_UNIT_CASE: 978/8 — readiness requested; positive activation
        // requires actual owner evidence (permit + receipts), never liveness
        // alone. This record precedes every validation below, so it names no
        // identity at all: the only identities available here come from the
        // candidate binding and the two receipts, and none of them is validated
        // until those checks run. Naming them now would let a refusal-path
        // record point at identities that are about to be rejected, and absent
        // identities render as explicit absence rather than being invented. The
        // validated contour is named by the two records emitted after the
        // `Active` transition commits.
        kernel_activation_observe(
            "host.kernel-activation readiness requested",
            &LaunchPhaseCorrelation::NONE,
        );
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
        // exact owner evidence above, exact errors propagate unchanged. Both
        // records are composed here, after the `Active` transition committed,
        // so every identity they name is the committed record's own already-
        // validated identity: its operation identity, approved artifact,
        // installation, activation fence and activation-generation sequence,
        // plus the Host-observed Kernel Job root process start identity (root
        // pid plus handle-observed creation time) projected from the Job
        // binding this driver retained at bind time. That projection is
        // genuinely Host-proven and stable across the contour, unlike the
        // Kernel-authored process handle this path used to bind; with no
        // retained Job binding the slot stays explicitly absent instead. No
        // receipt payload text, evidence reference or secret is ever bound.
        let mut correlation = LaunchPhaseCorrelation::NONE
            .with_installation(self.current.fence.host.installation.as_str())
            .with_generation(
                self.current
                    .fence
                    .activation_generation
                    .current
                    .sequence
                    .get(),
            )
            .with_operation(self.current.operation.operation_id.as_str())
            .with_artifact(self.current.approved_artifact_hash.as_str())
            .with_fence(self.current.fence.activation_id.as_str());
        // The projected string must outlive `correlation`, so it is bound here
        // rather than inside the `if let`; only the binding is conditional.
        let process_start = self
            .current
            .candidate_job_binding
            .as_ref()
            .map(|job_binding| {
                kernel_process_start_identity(
                    job_binding.root_pid,
                    job_binding.root_start_time_100ns,
                )
            });
        if let Some(process_start) = process_start.as_deref() {
            correlation = correlation.with_process_start(process_start);
        }
        kernel_activation_observe("host.kernel-activation activation observed", &correlation);
        kernel_activation_observe("host.kernel-activation readiness observed", &correlation);
        Ok(())
    }

    pub(super) fn fail(&mut self, evidence: &str) -> Result<(), HostError> {
        // WORK_UNIT_CASE: 978/10 — failure observed without owning a terminal;
        // the outermost #891 contour emits the single terminal. The record
        // names the contour identities held on the record, including its
        // retained Job root process start identity; the owner-supplied evidence
        // label stays owner-supplied and is never bound, and no typed reason
        // kind exists on this path to name.
        let mut correlation = LaunchPhaseCorrelation::NONE
            .with_installation(self.current.fence.host.installation.as_str())
            .with_generation(
                self.current
                    .fence
                    .activation_generation
                    .current
                    .sequence
                    .get(),
            )
            .with_operation(self.current.operation.operation_id.as_str())
            .with_artifact(self.current.approved_artifact_hash.as_str())
            .with_fence(self.current.fence.activation_id.as_str());
        // A failing contour still holds this activation's Job binding, so the failure
        // record names the same process incarnation the rest of the contour
        // names: projected exactly as `active` projects it, never invented.
        let process_start = self
            .current
            .candidate_job_binding
            .as_ref()
            .map(|job_binding| {
                kernel_process_start_identity(
                    job_binding.root_pid,
                    job_binding.root_start_time_100ns,
                )
            });
        if let Some(process_start) = process_start.as_deref() {
            correlation = correlation.with_process_start(process_start);
        }
        kernel_activation_observe("host.kernel-activation fail observed", &correlation);
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

/// Inline proof for this file's own observation seam (F-LOG-HOST-3, #978).
///
/// The cases below execute the real instrumented driver through the real #889
/// facade under a scoped subscriber, so what is asserted is what the retained
/// record actually renders — never a hand-constructed detail. Only paths that
/// need no live contour are covered here: `resume` merely retains a record, so
/// it needs no owner object, no Job, no process and no committed append. The
/// owner-evidence path (`active`) and every appending step keep their existing
/// journal-level proof in `journal_tests`/`tests.rs`, where a complete durable
/// activation contour is already built.
#[cfg(all(test, windows))]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use eliot_contracts::{AuthorityEpoch, EpochId};
    use eliot_host_state::MemoryBackend;
    use eliot_runtime_contracts::{
        HealthVector, SupervisionJournalEpoch, SupervisionLeaseIncarnationBinding,
    };

    use super::*;
    // `HostJobBinding`, `HostProcessBinding` and `RestartBudget` are re-exported
    // by the crate root (lib.rs), which is how production reaches them; the
    // owning module itself is private, so the test module uses the same path.
    use crate::{HostJobBinding, HostProcessBinding, RestartBudget, TestResult};

    /// Non-sensitive marker held by the retained candidate pipe identity. A
    /// pipe name is a name, not an identity, so it must never be rendered.
    const PIPE_CANARY: &str = "canary-candidate-pipe-978";

    /// Bounded facade output captured from the live instrumented driver.
    #[derive(Clone, Default)]
    struct CapturedRecords {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CapturedRecords {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs `driver_step` under a scoped subscriber and returns what the #889
    /// facade actually emitted while it executed.
    fn captured(driver_step: impl FnOnce()) -> String {
        let records = CapturedRecords::default();
        let writer = records.clone();
        let bytes = {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, driver_step);
            records
                .bytes
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .clone()
        };
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value).unwrap_or_else(|_| unreachable!())
    }

    /// One retained activation record exactly as a restarted Host finds it:
    /// an unissued nonce, no active pipe, no Job binding and no process record.
    ///
    /// The absent Job binding is deliberate: this fixture IS the no-retained-
    /// Job-binding path, so `process_start` must render the renderer's own
    /// explicit absence marker there. The bound path is proved on this same
    /// record, in the case below, once the Job binding a real activation
    /// retains at `bind_candidate` is installed on it.
    fn retained_record() -> Result<(HostInstallationEpoch, KernelRecord), crate::TestError> {
        let host = crate::fresh_host_epoch(handle("driver-resume-installation"), None)?;
        let activation_id = handle("driver-resume-activation");
        let activation_generation = crate::root_epoch(crate::fresh_lineage_id()?);
        let record = KernelRecord {
            fence: crate::record_fence(&host, &activation_id, &activation_generation),
            operation: crate::operation("kernel-resume-fixture")?,
            activation_identity: activation_id,
            approved_artifact_hash: handle(&"a".repeat(64)),
            active_pipe_identity: None,
            candidate_pipe_identity: Some(handle(PIPE_CANARY)),
            candidate_job_binding: None,
            prior_kernel_disposition: PriorKernelDisposition::NoPriorKernel,
            kernel_generation: crate::root_epoch(crate::fresh_lineage_id()?),
            one_time_nonce: OneTimeNonceState::unissued(),
            state: KernelActivationState::ShadowNoAuthority,
            process: None,
            readiness_evidence: Vec::new(),
            disposition_evidence: Vec::new(),
        };
        Ok((host, record))
    }

    // WORK_UNIT_CASE: 978/7 — the live driver names the identities the retained
    // record already holds, so concurrent and restarted activation contours
    // produce distinguishable records, and it names no secret: not the one-use
    // nonce, not the candidate pipe name, not a receipt payload.
    #[test]
    fn resume_record_names_retained_identities_and_no_secret() -> TestResult {
        let (host, record) = retained_record()?;
        let operation_id = record.operation.operation_id.clone();
        let generation = record.fence.activation_generation.current.sequence.get();
        // The same retained record once a restarted Host finds it WITH the Job
        // binding `bind_candidate` commits: a Job root pid paired with the
        // creation time Host itself observed on the live Job object, so the
        // process start identity is genuinely in hand and is projected from the
        // retained record rather than invented.
        let job = KernelJobBinding {
            job_name: handle("driver-resume-job"),
            owner: handle("Kernel"),
            root_pid: 42,
            root_start_time_100ns: 10,
            root_image_path: handle(KERNEL_IMAGE),
            root_volume_serial_number: 1,
            root_file_index: 2,
        };
        let process_start = kernel_process_start_identity(job.root_pid, job.root_start_time_100ns);
        let mut bound = record.clone();
        bound.candidate_job_binding = Some(job);
        let journal = HostStateJournalService::from_backend(MemoryBackend::default(), host)?;
        let first = captured(|| {
            let _driver = DurableKernelActivationDriver::resume(&journal, bound.clone());
        });
        // WORK_UNIT_CASE: 978/13 — the same retained record rendered twice is
        // byte-identical: the fields are deterministic, not order-dependent.
        let second = captured(|| {
            let _driver = DurableKernelActivationDriver::resume(&journal, bound.clone());
        });
        // The fixture's own default is the no-retained-Job-binding arm of the
        // SAME production call site, so the explicit absence render is proved
        // here instead of being inferred from the bound arm.
        let unbound = captured(|| {
            let _driver = DurableKernelActivationDriver::resume(&journal, record.clone());
        });

        assert!(
            first.contains("phase=host.kernel-activation resume requested"),
            "got: {first}"
        );
        assert!(
            first.contains("installation=driver-resume-installation"),
            "got: {first}"
        );
        assert!(
            first.contains(&format!("generation={generation}")),
            "got: {first}"
        );
        assert!(
            first.contains(&format!("operation={}", operation_id.as_str())),
            "got: {first}"
        );
        assert!(
            first.contains(&format!("artifact={}", "a".repeat(64))),
            "got: {first}"
        );
        assert!(
            first.contains("fence=driver-resume-activation"),
            "got: {first}"
        );
        // A resumed contour names the process start identity its retained Job
        // binding already carries — the Kernel root pid together with the
        // handle-observed creation time — because that identity is in hand: it
        // is read from the retained record, not re-derived, re-read or probed.
        // The bare pid is never the identity; the pair is. One record carries
        // one `process_start` slot, so this value cannot also read as absent.
        // It computes no typed outcome, so `reason` renders the renderer's own
        // explicit absence marker instead of an invented kind.
        assert!(
            first.contains(&format!("process_start={process_start}")),
            "the retained Job binding must reach the detail: {first}"
        );
        assert!(first.contains("reason="), "got: {first}");
        // No retained Job binding means the explicit absence marker and nothing
        // else: on this arm a start identity must not appear at all.
        assert!(
            unbound.contains("process_start=missing"),
            "no retained Job binding means the explicit absence marker: {unbound}"
        );
        assert!(
            !unbound.contains("pid:"),
            "no start identity may be invented without a retained binding: {unbound}"
        );
        assert!(!first.contains(PIPE_CANARY), "got: {first}");
        assert!(!unbound.contains(PIPE_CANARY), "got: {unbound}");
        assert!(
            !first.contains("nonce"),
            "no nonce may be observed: {first}"
        );
        // Only the owner-evidence path may claim readiness, and a resumed
        // contour has published none.
        assert!(!first.contains("readiness"), "got: {first}");
        assert_eq!(first, second, "one retained record must render one record");
        Ok(())
    }

    /// Non-secret installation identity shared by the executed contours below.
    const NONCE_INSTALLATION: &str = "driver-nonce-installation";

    /// Approved runtime generation deliberately different from the activation
    /// generation sequence, so the two `generation` slots can never be
    /// confused for each other in an emitted record.
    const RUNTIME_GENERATION: u64 = 7;

    /// Non-sensitive canary held by the candidate binding's own IPC identity.
    /// A pipe name is a name, not an identity, so it must never be rendered.
    const CANDIDATE_PIPE_CANARY: &str = "canary-978-candidate-binding-pipe";

    /// Non-sensitive canary for the owner-supplied failure evidence label. It
    /// stays owner-supplied and must never be bound into a record.
    const FAILURE_EVIDENCE_CANARY: &str = "canary-978-failure-evidence";

    /// Non-sensitive image identities: a raw path is never an observation.
    const HOST_IMAGE: &str = "C:\\eliot\\eliot-host.exe";
    const KERNEL_IMAGE: &str = "C:\\eliot\\eliot-kernel.exe";

    /// Every phase token this file emits on the executed activation contour.
    const BIND_REQUESTED: &str = "host.kernel-activation bind requested";
    const CANDIDATE_OBSERVED: &str = "host.kernel-activation candidate observed";
    const NONCE_REQUESTED: &str = "host.kernel-activation nonce requested";
    const NONCE_ISSUED: &str = "host.kernel-activation nonce issued";
    const ACTIVATING_REQUESTED: &str = "host.kernel-activation activating requested";
    const READINESS_REQUESTED: &str = "host.kernel-activation readiness requested";
    const READINESS_OBSERVED: &str = "host.kernel-activation readiness observed";
    const ACTIVATION_OBSERVED: &str = "host.kernel-activation activation observed";
    const FAIL_OBSERVED: &str = "host.kernel-activation fail observed";

    /// Runs `driver_step` under the same scoped subscriber as [`captured`] and
    /// returns what the #889 facade emitted together with exactly what the
    /// executed step produced, so a case can read the records and the real
    /// typed outcome of the same run instead of trusting the harness.
    fn captured_outcome<T>(driver_step: impl FnOnce() -> T) -> (String, T) {
        let records = CapturedRecords::default();
        let writer = records.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let mut produced = None;
        tracing::subscriber::with_default(subscriber, || {
            produced = Some(driver_step());
        });
        let produced = produced.unwrap_or_else(|| unreachable!("the scoped step runs once"));
        let bytes = records
            .bytes
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .clone();
        (String::from_utf8_lossy(&bytes).into_owned(), produced)
    }

    /// Counts non-overlapping occurrences of `needle` in captured records.
    fn count(haystack: &str, needle: &str) -> usize {
        haystack.matches(needle).count()
    }

    /// Returns the byte offset of the record carrying `phase`, so two records
    /// of one captured window can be compared for observed order.
    ///
    /// This is the byte-offset ordering idiom the card forbids in the
    /// integration target, and it is legitimate here only because of what this
    /// helper is given: one `records` string captured by a single
    /// [`captured`] or [`captured_outcome`] subscriber install, in which the
    /// #889 facade writes each phase detail as exactly one complete line. The
    /// offset comparison therefore reduces to comparing whole-record positions
    /// in one contiguous buffer, with no interleaved writer, no partial line and
    /// no substring that could straddle a record boundary. That inference does
    /// NOT survive elsewhere: the integration target reads records from a
    /// multi-subscriber process log where a record can be split across writes,
    /// where one line can carry several records, and where ordering is real
    /// process order rather than buffer position. Do not copy this ordering
    /// there.
    ///
    /// LIMITATION, stated rather than left implicit: unlike [`record_for`],
    /// this helper does not assert that `phase` occurs exactly once. It returns
    /// the FIRST match, so on a window where one phase was emitted more than
    /// once it compares first occurrences and silently proves nothing about
    /// later ones. Every ordering assertion below is therefore paired with a
    /// [`record_for`] lookup (or an explicit occurrence count) on the same
    /// window, so no claim in this file rests on an ambiguous offset.
    fn phase_offset(records: &str, phase: &str) -> usize {
        let needle = format!("phase={phase}");
        records
            .find(&needle)
            .unwrap_or_else(|| panic!("no record carries phase {phase}: {records}"))
    }

    /// Returns the one captured record line carrying `phase`, refusing to
    /// guess when the phase was emitted zero times or more than once.
    fn record_for<'a>(records: &'a str, phase: &str) -> &'a str {
        let needle = format!("phase={phase}");
        assert_eq!(
            count(records, &needle),
            1,
            "one underlying operation emits exactly one {phase} record: {records}"
        );
        records
            .lines()
            .find(|line| line.contains(&needle))
            .unwrap_or_else(|| panic!("no record line carries phase {phase}: {records}"))
    }

    /// Kernel authority epoch on its own lineage, so the rendered epoch
    /// identity is distinguishable from the activation generation sequence.
    fn driver_test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            crate::fresh_lineage_id().unwrap_or_else(|_| unreachable!()),
            std::num::NonZeroU64::new(sequence).unwrap_or_else(|| unreachable!()),
        )
        .unwrap_or_else(|_| unreachable!())
    }

    /// The supervision incarnation one candidate binding must carry, built
    /// through the contract's own derived-id projection.
    fn driver_supervision_incarnation(
        host: &HostInstallationEpoch,
        activation_id: &PlatformHandle,
    ) -> SupervisionLeaseIncarnationBinding {
        SupervisionLeaseIncarnationBinding {
            supervision_lease_scope_id: "eliot-supervision-scope:v1:test".to_owned(),
            supervision_lease_id: String::new(),
            scope_ref_digest: String::new(),
            installation_id: host.installation.as_str().to_owned(),
            host_epoch: SupervisionJournalEpoch {
                lineage_id: host.epoch.current.lineage_id.as_str().to_owned(),
                sequence: 1,
            },
            activation_id: activation_id.as_str().to_owned(),
            activation_generation: SupervisionJournalEpoch {
                lineage_id: "driver-activation-lineage".to_owned(),
                sequence: 1,
            },
            kernel_generation: SupervisionJournalEpoch {
                lineage_id: "driver-kernel-lineage".to_owned(),
                sequence: 1,
            },
            watchdog_epoch: SupervisionJournalEpoch {
                lineage_id: "driver-watchdog-lineage".to_owned(),
                sequence: 1,
            },
            observation_scope: eliot_runtime_contracts::canonical_observation_scope(),
            wake_policy: eliot_runtime_contracts::canonical_wake_policy(),
            predecessor: None,
        }
        .with_derived_ids()
        .unwrap_or_else(|_| unreachable!())
    }

    /// One complete durable activation contour: a real journal, a real
    /// activation fence, a real candidate binding and a real retained Job and
    /// process record. Nothing here stands in for an owner object.
    struct ActivationContour {
        host: HostInstallationEpoch,
        activation_id: PlatformHandle,
        activation_generation: EpochTransition,
        artifact: PlatformHandle,
        candidate: HostKernelCandidateBinding,
        durable_job: KernelJobBinding,
        process: ServiceProcessRecord,
        kernel_generation: EpochTransition,
        journal: HostStateJournalService<MemoryBackend>,
        generation: ResourceGeneration,
    }

    impl ActivationContour {
        #[allow(
            clippy::too_many_lines,
            reason = "the fixture establishes one complete durable activation contour for the executed driver cases"
        )]
        fn build() -> Result<Self, crate::TestError> {
            let host = crate::fresh_host_epoch(handle(NONCE_INSTALLATION), None)?;
            let activation_id = handle("driver-nonce-activation");
            let activation_generation = crate::root_epoch(crate::fresh_lineage_id()?);
            let artifact = handle(&"a".repeat(64));
            let config = handle(&"c".repeat(64));
            let job_name = handle("driver-nonce-job");
            let kernel_epoch = driver_test_epoch(2);
            let candidate = HostKernelCandidateBinding {
                installation_id: host.installation.clone(),
                host_epoch: AuthorityEpoch::new(host.epoch.current.sequence.get())?,
                kernel_epoch,
                activation_id: activation_id.clone(),
                artifact_hash: artifact.clone(),
                config_hash: config,
                job_object_id: job_name.clone(),
                pipe_identity: handle(CANDIDATE_PIPE_CANARY),
                host_process: HostProcessBinding {
                    process_id: 7,
                    start_time_100ns: 9,
                    image_path: HOST_IMAGE.to_owned(),
                },
                job_binding: HostJobBinding {
                    job: eliot_kernel_service::HostJobIdentity {
                        name: job_name.as_str().to_owned(),
                    },
                    root: eliot_kernel_service::HostJobRoot {
                        process: HostProcessBinding {
                            process_id: 42,
                            start_time_100ns: 10,
                            image_path: KERNEL_IMAGE.to_owned(),
                        },
                        executable: eliot_kernel_service::HostFileIdentity {
                            volume_serial_number: 1,
                            file_index: 2,
                        },
                    },
                },
                supervision_incarnation: driver_supervision_incarnation(&host, &activation_id),
                restart_budget: RestartBudget::new(1, 1)?,
                agent_bridge_admission: None,
                containment_action: None,
            };
            let durable_job = KernelJobBinding {
                job_name: job_name.clone(),
                owner: handle("Kernel"),
                root_pid: 42,
                root_start_time_100ns: 10,
                root_image_path: handle(KERNEL_IMAGE),
                root_volume_serial_number: 1,
                root_file_index: 2,
            };
            let process = ServiceProcessRecord {
                process_id: "pid:42:start:10".to_owned(),
                owner: "Kernel".to_owned(),
                state: ServiceProcessState::Starting,
                health: HealthVector::healthy(),
                authority_epoch: AuthorityEpoch::new(candidate.kernel_epoch.sequence.get())?,
            };
            let journal =
                HostStateJournalService::from_backend(MemoryBackend::default(), host.clone())?;
            let starting = crate::journal_append::initial_activation_record(
                &host,
                &activation_id,
                &activation_generation,
                crate::ActivationState::Starting,
                "driver-nonce-starting",
                &crate::journal_append::test_activation_ingress(),
            )?;
            append_reconciled(&journal, HostStateRecord::Activation(starting))?;
            Ok(Self {
                host,
                activation_id,
                activation_generation,
                artifact,
                candidate,
                durable_job,
                process,
                kernel_generation: crate::root_epoch(crate::fresh_lineage_id()?),
                journal,
                generation: ResourceGeneration::new(RUNTIME_GENERATION)?,
            })
        }

        /// Enters the real driver through its real production entry point.
        fn bind(&self) -> Result<MemoryDriver<'_>, HostError> {
            DurableKernelActivationDriver::bind_candidate(
                &self.journal,
                &self.host,
                &self.activation_id,
                &self.activation_generation,
                self.artifact.clone(),
                handle(PIPE_CANARY),
                self.durable_job.clone(),
                PriorKernelDisposition::NoPriorKernel,
                self.kernel_generation.clone(),
                self.process.clone(),
            )
        }

        /// The Kernel authority epoch the permit binds, rendered here only as
        /// an absence canary: it must reach no slot of any record below.
        fn authority_epoch_canary(&self) -> String {
            format!(
                "{}:{}",
                self.candidate.kernel_epoch.lineage_id.as_str(),
                self.candidate.kernel_epoch.sequence.get()
            )
        }

        /// The activation-generation sequence the record fence carries, which
        /// is a different identity from the approved runtime generation.
        fn activation_sequence(&self) -> u64 {
            self.activation_generation.current.sequence.get()
        }
    }

    /// The live driver over the in-memory journal these cases drive.
    type MemoryDriver<'a> = DurableKernelActivationDriver<'a, MemoryBackend>;

    /// Drives the real driver from candidate bind through the committed
    /// `OldTerminated` boundary: the only precondition nonce issuance is
    /// gated on, and it needs no live owner object.
    fn drive_to_old_terminated(contour: &ActivationContour) -> Result<MemoryDriver<'_>, HostError> {
        let mut driver = contour.bind()?;
        driver.handoff_prepared(None)?;
        driver.prior_disposition_committed()?;
        Ok(driver)
    }

    /// Drives the real driver from candidate bind through the committed
    /// `Activating` transition and returns the permit the run really issued.
    fn drive_to_activating(
        contour: &ActivationContour,
    ) -> Result<(MemoryDriver<'_>, KernelActivationPermit), HostError> {
        let mut driver = drive_to_old_terminated(contour)?;
        let permit = driver.issue_nonce(&contour.candidate, contour.generation)?;
        driver.activating()?;
        Ok((driver, permit))
    }

    /// A ready receipt that carries no readiness evidence reference. It is the
    /// absent-evidence case, never a fabricated owner observation.
    fn absent_evidence_ready_receipt(
        contour: &ActivationContour,
        activation: &KernelActivationReceipt,
    ) -> KernelReadyReceipt {
        KernelReadyReceipt {
            activation_id: contour.activation_id.clone(),
            activation_operation_id: activation.operation_id.clone(),
            activation_nonce_digest: activation.activation_nonce_digest.clone(),
            process: eliot_kernel_service::ProcessObservation {
                process_id: handle("pid:42:start:10"),
                job_object_id: contour.candidate.job_object_id.clone(),
                state: ServiceProcessState::Ready,
                health: HealthVector::healthy(),
                evidence_refs: vec![handle("driver-ready-process-proof")],
            },
            health: HealthVector::healthy(),
            evidence_refs: Vec::new(),
        }
    }

    /// What one executed nonce/activation window produced, including the typed
    /// outcomes and the operation identity each phase actually held, so no
    /// assertion can claim a step that did not run.
    struct DrivenWindow {
        issued_permit: Result<KernelActivationPermit, HostError>,
        requested_operation: PlatformHandle,
        issued_operation: PlatformHandle,
        activating_operation: PlatformHandle,
        activating: Result<(), HostError>,
    }

    /// The non-secret receipt payload one activation actually carried, so the
    /// case can prove that none of it reaches a readiness record.
    struct ReceiptPayload {
        candidate_binding_digest: String,
        prior_kernel_disposition_digest: String,
        nonce_digest: String,
        transaction_id: PlatformHandle,
    }

    /// The durable state, the activation outcome and the receipt payload one
    /// complete contour run left behind, read back after it returned.
    struct ContourRun {
        state: KernelActivationState,
        activation: Result<(), HostError>,
        payload: ReceiptPayload,
    }

    /// The nonce/handshake/activation distinctness case is already marked on
    /// this file's production call sites; this executes those sites and reads
    /// the records back out of the real facade.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the case asserts the whole nonce/activation record boundary, and splitting it would hide the identities under proof"
    )]
    fn nonce_and_activation_phases_stay_distinct_and_reach_no_secret() -> TestResult {
        let contour = ActivationContour::build()?;
        let mut driver = drive_to_old_terminated(&contour)?;
        let (records, window) = captured_outcome(|| {
            let requested_operation = driver.current.operation.operation_id.clone();
            let issued_permit = driver.issue_nonce(&contour.candidate, contour.generation);
            let issued_operation = driver.current.operation.operation_id.clone();
            let activating = driver.activating();
            DrivenWindow {
                issued_permit,
                requested_operation,
                issued_operation,
                activating_operation: driver.current.operation.operation_id.clone(),
                activating,
            }
        });
        let DrivenWindow {
            issued_permit,
            requested_operation,
            issued_operation,
            activating_operation,
            activating,
        } = window;
        let permit = issued_permit?;
        activating?;

        // One record per underlying operation across the three phases this
        // file owns on the nonce/activation contour, in the order the contour
        // performed them, with no dedup cache and no extra emission.
        assert_eq!(
            count(&records, "host.entrypoint_stage"),
            3,
            "three underlying phases emit three subordinate records: {records}"
        );
        assert!(
            phase_offset(&records, NONCE_REQUESTED) < phase_offset(&records, NONCE_ISSUED),
            "the request precedes the issued record: {records}"
        );
        assert!(
            phase_offset(&records, NONCE_ISSUED) < phase_offset(&records, ACTIVATING_REQUESTED),
            "issuance precedes activation: {records}"
        );
        let requested = record_for(&records, NONCE_REQUESTED);
        let issued = record_for(&records, NONCE_ISSUED);
        let activating_record = record_for(&records, ACTIVATING_REQUESTED);
        // Each phase names the exact operation identity the driver held when
        // it emitted, and the permit's own identity is the issued one.
        assert!(
            requested.contains(&format!("operation={}", requested_operation.as_str())),
            "the request names the pre-issuance operation identity: {requested}"
        );
        assert!(
            issued.contains(&format!("operation={}", issued_operation.as_str())),
            "the issued record names the exact permit operation identity: {issued}"
        );
        assert_eq!(
            permit.operation_id, issued_operation,
            "the issued record must name the permit the run really issued"
        );
        assert_ne!(
            requested_operation, issued_operation,
            "the committed NonceIssued append must mint its own operation identity"
        );
        assert!(
            activating_record.contains(&format!("operation={}", issued_operation.as_str())),
            "the activating record is emitted before its own append: {activating_record}"
        );
        assert!(
            !records.contains(&format!("operation={}", activating_operation.as_str())),
            "a record must never name a transition identity minted after it: {records}"
        );
        assert_ne!(
            issued_operation, activating_operation,
            "each committed append must mint its own operation identity"
        );
        // The approved runtime generation reaches the detail on the two nonce
        // records and the record's own activation-generation sequence on the
        // activation record, so the two generation slots never borrow each
        // other's value.
        let runtime_generation = format!("generation={}", contour.generation.value());
        let activation_generation = format!("generation={}", contour.activation_sequence());
        assert_ne!(
            runtime_generation, activation_generation,
            "the fixture must keep the two generation slots distinguishable"
        );
        // The one process start identity this contour holds, projected from the
        // Job binding the contour really committed — the same projection the
        // production call sites make, so the expectation is read rather than
        // hand-written.
        let process_start = kernel_process_start_identity(
            contour.durable_job.root_pid,
            contour.durable_job.root_start_time_100ns,
        );
        for record in [requested, issued, activating_record] {
            assert!(
                record.contains(&format!("installation={NONCE_INSTALLATION}")),
                "the held installation must reach the detail: {record}"
            );
            assert!(
                record.contains(&format!("artifact={}", contour.artifact.as_str())),
                "the approved artifact must reach the detail: {record}"
            );
            assert!(
                record.contains(&format!("fence={}", contour.activation_id.as_str())),
                "the activation fence of the committed record must reach the detail: {record}"
            );
            // This contour DID bind a candidate, so every record of it already
            // holds the retained Job binding, and the slot names the Host-observed
            // Kernel Job root process start identity it carries: the root pid
            // together with the handle-observed creation time. Rendering `missing`
            // here would be a false reason, because the identity is in hand.
            assert!(
                record.contains(&format!("process_start={process_start}")),
                "the retained Job binding must reach the detail: {record}"
            );
            assert!(
                !record.contains("process_start=missing"),
                "a held process start identity must never render as absent: {record}"
            );
            assert!(record.contains("reason=missing"), "got: {record}");
        }
        // The Kernel authority epoch the permit binds reaches no slot on this
        // contour: `fence` keeps exactly one meaning, so the epoch is named
        // nowhere rather than displacing the activation identity.
        let authority_epoch = contour.authority_epoch_canary();
        assert!(
            !records.contains(&authority_epoch),
            "the authority epoch must reach no slot: {records}"
        );
        assert!(
            !records.contains(contour.candidate.kernel_epoch.lineage_id.as_str()),
            "no Kernel epoch lineage may reach a record: {records}"
        );
        assert!(requested.contains(&runtime_generation), "got: {requested}");
        assert!(issued.contains(&runtime_generation), "got: {issued}");
        assert!(
            activating_record.contains(&activation_generation),
            "the activation record carries the record's own generation: {activating_record}"
        );
        // The one-use secret never reaches a record. The permit's published
        // non-secret nonce digest is exactly what a bound nonce would render,
        // and it is absent from every record.
        let nonce_digest = permit.activation_nonce_digest();
        assert!(
            !records.contains(&nonce_digest),
            "no nonce-derived value may reach a record: {records}"
        );
        assert!(
            !records.contains(permit.journal_transaction_id.as_str()),
            "the committed NonceIssued transaction identity stays unobserved: {records}"
        );
        assert!(
            !records.contains(&permit.candidate_binding_digest),
            "candidate binding payload text is not an identity: {records}"
        );
        assert!(
            !records.contains(&permit.prior_kernel_disposition_digest),
            "prior disposition payload text is not an identity: {records}"
        );
        // Names and paths are not identities. The one process start identity that IS
        // in hand is the retained Job root one, and it is the only start identity
        // any record of this contour may name: the Host-side process binding
        // this same candidate carries (pid 7) is a different process and is not
        // what the slot means, so its absence is asserted rather than assumed.
        assert!(!records.contains(PIPE_CANARY), "got: {records}");
        assert!(!records.contains(CANDIDATE_PIPE_CANARY), "got: {records}");
        assert!(!records.contains(KERNEL_IMAGE), "got: {records}");
        assert!(!records.contains(HOST_IMAGE), "got: {records}");
        assert!(
            !records.contains('\\'),
            "no raw path may reach a record: {records}"
        );
        assert!(
            !records.contains("pid:7:"),
            "only the retained Job root start identity may be named: {records}"
        );
        assert_eq!(
            count(&records, &format!("process_start={process_start}")),
            3,
            "the held identity is projected once per record and nowhere else: {records}"
        );
        assert_eq!(
            count(&records, "process_start="),
            3,
            "every process_start slot of this window carries that one identity: {records}"
        );
        Ok(())
    }

    // WORK_UNIT_CASE: 978/8
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the case keeps the observed phase order and the evidence boundary in one executed run"
    )]
    fn readiness_is_requested_before_validation_and_claimed_only_on_owner_evidence() -> TestResult {
        let contour = ActivationContour::build()?;
        let (records, run) = captured_outcome(|| -> Result<ContourRun, HostError> {
            let (mut driver, permit) = drive_to_activating(&contour)?;
            let activation = KernelActivationReceipt::issue(&permit);
            let ready = absent_evidence_ready_receipt(&contour, &activation);
            let outcome = driver.active(&contour.candidate, &activation, &ready);
            Ok(ContourRun {
                state: driver.current.state,
                activation: outcome,
                payload: ReceiptPayload {
                    candidate_binding_digest: permit.candidate_binding_digest.clone(),
                    prior_kernel_disposition_digest: permit.prior_kernel_disposition_digest.clone(),
                    nonce_digest: permit.activation_nonce_digest(),
                    transaction_id: permit.journal_transaction_id.clone(),
                },
            })
        });
        let run = run?;

        // One subordinate record per underlying operation, in the order the
        // contour performed them: the readiness request is the last phase of
        // this contour and nothing follows it.
        assert_eq!(
            count(&records, "host.entrypoint_stage"),
            6,
            "one subordinate record per underlying phase: {records}"
        );
        let mut previous = 0;
        for phase in [
            BIND_REQUESTED,
            CANDIDATE_OBSERVED,
            NONCE_REQUESTED,
            NONCE_ISSUED,
            ACTIVATING_REQUESTED,
            READINESS_REQUESTED,
        ] {
            let at = phase_offset(&records, phase);
            assert!(
                at > previous,
                "phase {phase} must follow the preceding record: {records}"
            );
            // `phase_offset` returns the FIRST match and does not assert
            // uniqueness, so the occurrence count is asserted here for every
            // phase this ordering loop touches: no offset compared above is an
            // ambiguous one.
            assert_eq!(
                count(&records, &format!("phase={phase}")),
                1,
                "one record per underlying operation, so the offset is unique: {records}"
            );
            previous = at;
        }
        // `active` refuses, so the request it emitted cannot be a
        // post-validation projection: the request precedes validation, and no
        // readiness claim is ever reached on this path.
        assert!(
            run.activation.is_err(),
            "an activation without owner evidence must never publish: {records}"
        );
        assert_ne!(
            run.state,
            KernelActivationState::Active,
            "no committed transition may mark the Kernel active: {records}"
        );
        assert_eq!(
            count(&records, &format!("phase={ACTIVATION_OBSERVED}")),
            0,
            "the activation claim follows owner evidence: {records}"
        );
        assert_eq!(
            count(&records, &format!("phase={READINESS_OBSERVED}")),
            0,
            "readiness is never claimed without owner evidence: {records}"
        );
        assert_eq!(
            count(&records, "readiness"),
            1,
            "only the readiness request may name readiness: {records}"
        );
        assert_eq!(
            count(&records, "host.terminal_error"),
            0,
            "this contour owns no terminal at all: {records}"
        );
        // The request precedes every validation below it, so it names no
        // identity at all: every slot renders the renderer's own explicit
        // absence marker rather than an identity the run is about to reject.
        let requested = record_for(&records, READINESS_REQUESTED);
        for slot in [
            "installation",
            "generation",
            "operation",
            "artifact",
            "process_start",
            "fence",
            "reason",
        ] {
            assert!(
                requested.contains(&format!("{slot}=missing")),
                "an unvalidated readiness request must name no {slot}: {requested}"
            );
        }
        // None of the identities this contour really holds is named by the
        // request either, so a refusal-path record can never point at a
        // contour the validation then rejects.
        for withheld in [
            NONCE_INSTALLATION,
            contour.activation_id.as_str(),
            contour.artifact.as_str(),
            contour.candidate.kernel_epoch.lineage_id.as_str(),
        ] {
            assert!(
                !requested.contains(withheld),
                "the readiness request must name no unvalidated identity: {requested}"
            );
        }
        assert!(
            !requested.contains(CANDIDATE_PIPE_CANARY) && !requested.contains(PIPE_CANARY),
            "no pipe name may reach the request: {requested}"
        );
        // No receipt payload text reaches the request either, including the
        // published non-secret digest of the consumed nonce.
        for payload in [
            run.payload.candidate_binding_digest.as_str(),
            run.payload.prior_kernel_disposition_digest.as_str(),
            run.payload.nonce_digest.as_str(),
            run.payload.transaction_id.as_str(),
        ] {
            assert!(
                !records.contains(payload),
                "no receipt payload text may reach a readiness record: {records}"
            );
        }
        // The positive arm of this case is not reachable in-crate, and this
        // test does not fake it: `active` opens with `prove_candidate_owner_held`,
        // which is satisfied only when a live candidate Kernel process already
        // holds the exclusive owner object for this exact
        // installation/activation pair. Standing one up from inside the test
        // process would fabricate the very owner evidence the guard exists to
        // prove, so the committed `Active` arm, and with it
        // `activation observed` and `readiness observed`, is left unproven here
        // rather than asserted on a stand-in owner. What this case does prove
        // is the whole reachable boundary: the request is emitted before the
        // validation that decides it, and neither claim is reachable on any
        // path this crate can drive without that live owner object.
        Ok(())
    }

    /// The single-terminal propagation case is already marked on this file's
    /// production call sites; this executes the failure contour itself.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the case keeps the failure record, the absent terminal and the repeated underlying call in one run"
    )]
    fn a_failed_activation_emits_one_subordinate_record_and_no_terminal() -> TestResult {
        let contour = ActivationContour::build()?;
        let (mut driver, _permit) = drive_to_activating(&contour)?;
        let observed_operation = driver.current.operation.operation_id.clone();

        let (records, failed) = captured_outcome(|| driver.fail(FAILURE_EVIDENCE_CANARY));
        failed?;
        let failed_operation = driver.current.operation.operation_id.clone();

        // The designated terminal for one failed activation belongs to the
        // outermost #891 contour in `lib.rs`; this file owns none, so a failure
        // here must produce none.
        assert_eq!(
            count(&records, "host.terminal_error"),
            0,
            "the single terminal stays with the outermost contour: {records}"
        );
        // Exactly one correlated subordinate phase record for the one
        // underlying failure, carrying the identities the record held.
        assert_eq!(
            count(&records, "host.entrypoint_stage"),
            1,
            "one failure emits one subordinate record: {records}"
        );
        let failed_record = record_for(&records, FAIL_OBSERVED);
        assert!(
            failed_record.contains(&format!("installation={NONCE_INSTALLATION}")),
            "got: {failed_record}"
        );
        assert!(
            failed_record.contains(&format!("generation={}", contour.activation_sequence())),
            "got: {failed_record}"
        );
        assert!(
            failed_record.contains(&format!("operation={}", observed_operation.as_str())),
            "the failure record names the operation it observed: {failed_record}"
        );
        assert!(
            failed_record.contains(&format!("artifact={}", contour.artifact.as_str())),
            "got: {failed_record}"
        );
        assert!(
            failed_record.contains(&format!("fence={}", contour.activation_id.as_str())),
            "got: {failed_record}"
        );
        // A failing contour still holds this activation's retained Job binding,
        // so the failure record names the same Kernel root process start
        // identity every other record of the contour names — projected from the
        // retained binding, never invented, and never a bare reusable pid.
        let process_start = kernel_process_start_identity(
            contour.durable_job.root_pid,
            contour.durable_job.root_start_time_100ns,
        );
        assert!(
            failed_record.contains(&format!("process_start={process_start}")),
            "the retained Job binding must reach the failure record: {failed_record}"
        );
        assert!(
            !failed_record.contains("process_start=missing"),
            "a held process start identity must never render as absent: {failed_record}"
        );
        assert!(
            !failed_record.contains(&format!("operation={}", failed_operation.as_str())),
            "a record must not name the transition it is about to perform: {failed_record}"
        );
        assert_ne!(
            observed_operation, failed_operation,
            "the failure append must mint its own operation identity"
        );
        // Owner-supplied evidence and names stay owner-supplied.
        assert!(
            !records.contains(FAILURE_EVIDENCE_CANARY),
            "the owner-supplied evidence label stays unobserved: {records}"
        );
        assert!(!records.contains(PIPE_CANARY), "got: {records}");
        assert!(!records.contains(CANDIDATE_PIPE_CANARY), "got: {records}");
        assert!(
            !records.contains("host.kernel-activation readiness observed"),
            "a failed contour never claimed readiness: {records}"
        );

        // A second failure is a new underlying call on an already-failed
        // contour: it gets its own correlated subordinate record because there
        // is no dedup cache or suppression flag, and still no terminal.
        let (repeat, repeated) = captured_outcome(|| driver.fail(FAILURE_EVIDENCE_CANARY));
        repeated?;
        assert_eq!(
            count(&repeat, "host.entrypoint_stage"),
            1,
            "each underlying failure call emits its own record: {repeat}"
        );
        assert_eq!(
            count(&repeat, "host.terminal_error"),
            0,
            "still no terminal from this contour: {repeat}"
        );
        let repeat_record = record_for(&repeat, FAIL_OBSERVED);
        assert!(
            repeat_record.contains(&format!("process_start={process_start}")),
            "the repeated failure names the same retained Job binding: {repeat_record}"
        );
        assert_eq!(
            driver.current.operation.operation_id, failed_operation,
            "an already-failed contour performs no further append"
        );
        Ok(())
    }
}
