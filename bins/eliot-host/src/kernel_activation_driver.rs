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
// failed activation stays with the outermost #891 contour (e.g.
// `host-start-failed` / `host-resume-pending-failed` in `lib.rs`). This
// coordinates the "one terminal across nesting" rule with #891.
//
// Bounded identities, not stage order alone (audit 5910159678 defects 3 and 5):
// a call site passes a static phase token plus a
// `LaunchPhaseCorrelation` built only from identities this driver already
// holds — the KernelRecord operation identity, the approved artifact hash
// handle, the installation handle and activation id on the record fence, the
// Kernel Job root process start identity at bind time, and the issued permit's
// authority epoch where a permit already exists. `generation` carries the
// approved runtime generation where a permit, receipt or request holds one, and
// the record's activation-generation sequence otherwise. Nothing is re-derived,
// re-read, re-verified or probed to obtain a field: an absent identity renders
// as the renderer's own explicit absence marker instead of being invented.
//
// Secrets and payloads never cross this boundary. The one-use permit secret is
// never bound or observed in any form, and neither is the nonce state value,
// receipt or health payload text, evidence reference handles, pipe identities,
// credential material, or arbitrary error text — including the owner-supplied
// failure evidence label, which stays owner-supplied. An authority epoch is
// rendered as the owner's own lineage id plus sequence pair, and a process
// start identity as the owner's own pid/start pair, so a record names the
// contour that produced it without naming a payload. Bounding limits size, not
// sensitivity (I15.4). Sink outcome never alters result/order/status/cleanup.
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

/// Renders one held authority epoch as its owner's lineage id plus sequence.
#[cfg(windows)]
fn authority_epoch_identity(lineage_id: &str, sequence: u64) -> String {
    format!("{lineage_id}:{sequence}")
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
        let correlation = LaunchPhaseCorrelation::NONE
            .with_installation(current.fence.host.installation.as_str())
            .with_generation(current.fence.activation_generation.current.sequence.get())
            .with_operation(current.operation.operation_id.as_str())
            .with_artifact(current.approved_artifact_hash.as_str())
            .with_fence(current.fence.activation_id.as_str());
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
        // never observed, and the authority epoch this permit will bind plus the
        // approved runtime generation are named from the held candidate.
        let requested_epoch = authority_epoch_identity(
            candidate.kernel_epoch.lineage_id.as_str(),
            candidate.kernel_epoch.sequence.get(),
        );
        let correlation = LaunchPhaseCorrelation::NONE
            .with_installation(self.current.fence.host.installation.as_str())
            .with_generation(generation.value())
            .with_operation(self.current.operation.operation_id.as_str())
            .with_artifact(self.current.approved_artifact_hash.as_str())
            .with_fence(&requested_epoch);
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
        // operation identity, journal generation and validated authority epoch
        // are named; its one-use secret and the committed journal transaction
        // identity stay unobserved because no bound field carries them.
        let issued_epoch = authority_epoch_identity(
            permit.authority_epoch.lineage_id.as_str(),
            permit.authority_epoch.sequence.get(),
        );
        let correlation = LaunchPhaseCorrelation::NONE
            .with_installation(self.current.fence.host.installation.as_str())
            .with_generation(permit.generation.value())
            .with_operation(permit.operation_id.as_str())
            .with_artifact(self.current.approved_artifact_hash.as_str())
            .with_fence(&issued_epoch);
        kernel_activation_observe("host.kernel-activation nonce issued", &correlation);
        Ok(permit)
    }

    pub(super) fn activating(&mut self) -> Result<(), HostError> {
        // WORK_UNIT_CASE: 978/7 — activating requested; forbidden before the
        // committed NonceIssued receipt, distinct from nonce issuance. Where the
        // permit already exists its validated authority epoch is named; before
        // one exists the record keeps the fence's own activation identity
        // instead, and no epoch is invented.
        let permit_authority_epoch: Option<String> = self.issued_permit.as_ref().map(|permit| {
            authority_epoch_identity(
                permit.authority_epoch.lineage_id.as_str(),
                permit.authority_epoch.sequence.get(),
            )
        });
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
        if let Some(epoch) = permit_authority_epoch.as_deref() {
            correlation = correlation.with_fence(epoch);
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
    /// This is the only place that may claim Kernel readiness: the exclusive
    /// owner probe, the issued permit, the activation receipt and the ready
    /// receipt are validated and the `Active` transition is committed before
    /// either record below is emitted. A running process, a returned launch
    /// child or an IPC acknowledgement never produces this claim.
    pub(super) fn active(
        &mut self,
        candidate: &HostKernelCandidateBinding,
        activation_receipt: &KernelActivationReceipt,
        ready: &KernelReadyReceipt,
    ) -> Result<(), HostError> {
        // WORK_UNIT_CASE: 978/8 — readiness requested; positive activation
        // requires actual owner evidence (permit + receipts), never liveness
        // alone. The record names the exact contour this request concerns
        // before validation, because the validation below is what decides
        // whether readiness may ever be claimed for it.
        let requested_epoch = authority_epoch_identity(
            candidate.kernel_epoch.lineage_id.as_str(),
            candidate.kernel_epoch.sequence.get(),
        );
        let correlation = LaunchPhaseCorrelation::NONE
            .with_installation(candidate.installation_id.as_str())
            .with_generation(activation_receipt.generation.value())
            .with_operation(activation_receipt.operation_id.as_str())
            .with_artifact(candidate.artifact_hash.as_str())
            .with_process_start(ready.process.process_id.as_str())
            .with_fence(&requested_epoch);
        kernel_activation_observe("host.kernel-activation readiness requested", &correlation);
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
        // records carry the same validated identities, and no receipt payload
        // text is ever bound.
        kernel_activation_observe("host.kernel-activation activation observed", &correlation);
        kernel_activation_observe("host.kernel-activation readiness observed", &correlation);
        Ok(())
    }

    pub(super) fn fail(&mut self, evidence: &str) -> Result<(), HostError> {
        // WORK_UNIT_CASE: 978/10 — failure observed without owning a terminal;
        // the outermost #891 contour emits the single terminal. The record
        // names the contour identities held on the record; the owner-supplied
        // evidence label stays owner-supplied and is never bound, and no typed
        // reason kind exists on this path to name.
        let correlation = LaunchPhaseCorrelation::NONE
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

    use eliot_host_state::MemoryBackend;

    use super::*;
    use crate::TestResult;

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
        let journal = HostStateJournalService::from_backend(MemoryBackend::default(), host)?;
        let first = captured(|| {
            let _driver = DurableKernelActivationDriver::resume(&journal, record.clone());
        });
        // WORK_UNIT_CASE: 978/13 — the same retained record rendered twice is
        // byte-identical: the fields are deterministic, not order-dependent.
        let second = captured(|| {
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
        // A resume holds no process start identity and computes no typed
        // outcome, so both slots render the renderer's own explicit absence
        // marker instead of an invented identity. The absence itself is what
        // this proves, so the assertion stays independent of that marker's
        // spelling: no `pid:` start identity and no outcome kind may appear.
        assert!(first.contains("process_start="), "got: {first}");
        assert!(first.contains("reason="), "got: {first}");
        assert!(
            !first.contains("pid:"),
            "no start identity may be invented: {first}"
        );
        assert!(!first.contains(PIPE_CANARY), "got: {first}");
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
}
