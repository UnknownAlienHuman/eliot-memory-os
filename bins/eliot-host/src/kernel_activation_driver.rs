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
// (`super::host_diagnostics::observe_entrypoint_with_detail`,
// `super::host_job_launch::render_launch_identity`); the Event Log seam stays
// typed-Unavailable
// (`super::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open). No terminal is owned here: the single terminal for a
// failed activation stays with the outermost #891 contour (e.g.
// `host-start-failed` / `host-resume-pending-failed` in `lib.rs`). This
// coordinates the "one terminal across nesting" rule with #891.
//
// Identity binding (audit #5910159678 defect 5): this driver already holds the
// exact activation id and generation, the activation operation id, the journal
// transaction identity and sequence of every committed append, the candidate
// Job/process binding, the Kernel authority epoch, and the issued permit's and
// receipts' digests — yet every record used to be one identical static string,
// which made the deterministic fields vacuous and left nested operations
// indistinguishable. Every record now binds the identities the driver holds at
// that point: the installation identity and epoch sequence, the activation
// identity and its generation sequence, the current activation operation id,
// the committed journal transaction identity and sequence, the Kernel
// generation sequence, the approved artifact digest, the candidate Job binding
// name, the candidate root process start identity (`pid/creation-time`), the
// authority epoch, and the receipt evidence counts. A slot the driver does not
// hold at that point reads `unavailable`; nothing is invented.
//
// Never-logged (I15.4, I07.20): the activation nonce (raw or digested), the
// pipe identities, the image paths inside the Job binding, the evidence
// reference handles, and any `Debug`/`Display` of an error. Those stay with
// their owners and reach only the journal record and the typed error.
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner, so sink outcome never alters
// result/order/status/cleanup. There is no mutable global dedup cache.
#[cfg(windows)]
fn kernel_activation_note_event_log_unavailable() {
    let _ = super::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn kernel_activation_observe_bound(
    detail: &str,
    fields: &[(
        &'static str,
        super::host_job_launch::LaunchIdentityField<'_>,
    )],
) {
    kernel_activation_note_event_log_unavailable();
    super::host_diagnostics::observe_entrypoint_with_detail(
        super::host_diagnostics::EntrypointStage::Startup,
        &super::host_job_launch::render_launch_identity(detail, fields),
    );
}

/// The bounded, non-secret identity slots projected from one
/// [`KernelRecord`](super::KernelRecord) this driver currently holds.
///
/// Every value is a field of the retained record: the fence's installation
/// identity and epoch sequence, the activation identity and its generation
/// sequence, the current activation operation id, the Kernel generation
/// sequence, the approved artifact digest, and — where the record has bound a
/// candidate Job — that Job's name and the candidate root process start
/// identity. A record that has not yet bound a candidate (before `bind_candidate`,
/// or on a resumed activation whose candidate binding is absent) reports those
/// slots as explicitly unavailable rather than defaulting them.
#[cfg(windows)]
type ActivationIdentityFields<'a> = Vec<(
    &'static str,
    super::host_job_launch::LaunchIdentityField<'a>,
)>;

#[cfg(windows)]
struct ActivationRecordIdentity<'a> {
    record: &'a KernelRecord,
    /// The candidate root process start identity, rendered once as
    /// `pid/creation-time` from the retained candidate Job binding.
    ///
    /// This is owned rather than borrowed because it is composed here from two
    /// numeric bindings rather than read out of an existing handle. Owning it
    /// lets the projected identity slots below borrow the rendering for exactly
    /// as long as the projection lives, instead of borrowing a temporary that
    /// would be dropped before the record is emitted. It is still a pure
    /// rendering of the retained binding: no process is opened or queried.
    candidate_process: Option<String>,
}

#[cfg(windows)]
impl<'a> ActivationRecordIdentity<'a> {
    /// Projects one retained record into its identity slots.
    ///
    /// The candidate root process start identity is rendered here, once, from
    /// the binding this record holds; a record with no candidate binding has
    /// none to render and the slot reads explicitly unavailable.
    fn new(record: &'a KernelRecord) -> Self {
        let candidate_process = record
            .candidate_job_binding
            .as_ref()
            .map(|binding| format!("{}/{}", binding.root_pid, binding.root_start_time_100ns));
        Self {
            record,
            candidate_process,
        }
    }

    /// Appends one more already-held slot to a rendered field list.
    ///
    /// A static helper rather than a builder method so each emission site reads
    /// as one flat list of the identities it holds.
    fn with<'b>(
        fields: ActivationIdentityFields<'b>,
        key: &'static str,
        value: super::host_job_launch::LaunchIdentityField<'b>,
    ) -> ActivationIdentityFields<'b> {
        let mut fields = fields;
        fields.push((key, value));
        fields
    }

    fn base(&self) -> ActivationIdentityFields<'_> {
        vec![
            (
                "installation",
                super::host_job_launch::LaunchIdentityField::Text(
                    self.record.fence.host.installation.as_str(),
                ),
            ),
            (
                "host_epoch",
                super::host_job_launch::LaunchIdentityField::Number(
                    self.record.fence.host.epoch.current.sequence.get(),
                ),
            ),
            (
                "activation",
                super::host_job_launch::LaunchIdentityField::Text(
                    self.record.activation_identity.as_str(),
                ),
            ),
            (
                "activation_generation",
                super::host_job_launch::LaunchIdentityField::Number(
                    self.record
                        .fence
                        .activation_generation
                        .current
                        .sequence
                        .get(),
                ),
            ),
            (
                "operation",
                super::host_job_launch::LaunchIdentityField::Text(
                    self.record.operation.operation_id.as_str(),
                ),
            ),
            (
                "kernel_generation",
                super::host_job_launch::LaunchIdentityField::Number(
                    self.record.kernel_generation.current.sequence.get(),
                ),
            ),
            (
                "artifact_digest",
                super::host_job_launch::LaunchIdentityField::Text(
                    self.record.approved_artifact_hash.as_str(),
                ),
            ),
            (
                "activation_state",
                super::host_job_launch::LaunchIdentityField::Text(kernel_activation_state_name(
                    self.record.state,
                )),
            ),
        ]
    }

    /// The base slots plus the committed journal identity of one append.
    ///
    /// `receipt` is the exact [`AppendReceipt`] the semantic transition just
    /// produced, so the record names the transaction identity and sequence the
    /// journal actually assigned. The driver does not read the journal to
    /// obtain them.
    fn with_journal<'b>(&'b self, receipt: &'b AppendReceipt) -> ActivationIdentityFields<'b> {
        let mut fields = self.base();
        fields.push((
            "journal_transaction",
            super::host_job_launch::LaunchIdentityField::Text(receipt.transaction_id().as_str()),
        ));
        fields.push((
            "journal_sequence",
            super::host_job_launch::LaunchIdentityField::Number(receipt.sequence()),
        ));
        fields
    }

    /// The base slots plus the committed journal identity of one append and
    /// the candidate Job binding this record holds.
    ///
    /// This is the full identity of one committed activation transition: what
    /// the fence and operation are, where the journal put it, and which
    /// candidate process incarnation it is about.
    fn with_journal_and_candidate<'b>(
        &'b self,
        receipt: &'b AppendReceipt,
    ) -> ActivationIdentityFields<'b> {
        let mut fields = self.with_candidate();
        fields.push((
            "journal_transaction",
            super::host_job_launch::LaunchIdentityField::Text(receipt.transaction_id().as_str()),
        ));
        fields.push((
            "journal_sequence",
            super::host_job_launch::LaunchIdentityField::Number(receipt.sequence()),
        ));
        fields
    }

    /// The base slots plus the candidate Job binding this record holds.
    ///
    /// The Job name and the root process start identity come from the
    /// candidate binding the driver bound; the root image path inside that
    /// binding is a path and is never recorded. A record with no candidate
    /// binding reports both slots as unavailable.
    fn with_candidate(&self) -> ActivationIdentityFields<'_> {
        let mut fields = self.base();
        let Some(binding) = self.record.candidate_job_binding.as_ref() else {
            fields.push((
                "candidate_job",
                super::host_job_launch::LaunchIdentityField::Unavailable,
            ));
            fields.push((
                "candidate_process",
                super::host_job_launch::LaunchIdentityField::Unavailable,
            ));
            return fields;
        };
        fields.push((
            "candidate_job",
            super::host_job_launch::LaunchIdentityField::Text(binding.job_name.as_str()),
        ));
        // The root process start identity is the pair that distinguishes this
        // candidate process incarnation from a later process reusing its PID.
        // It was rendered from the retained binding by [`Self::new`]; no process
        // is opened or queried to obtain it.
        fields.push((
            "candidate_process",
            match self.candidate_process.as_deref() {
                Some(process) => super::host_job_launch::LaunchIdentityField::Text(process),
                None => super::host_job_launch::LaunchIdentityField::Unavailable,
            },
        ));
        fields
    }
}

/// Identity slots one readiness request contributes to a record.
///
/// This is the only owner-evidence path in the whole Host launch slice that
/// may claim readiness, so the request record states the exact identities the
/// evidence will be checked against: the candidate's activation identity, the
/// Kernel authority epoch, and the ready receipt's activation and operation
/// identities, beside the base slots and the candidate Job binding the driver
/// holds. A request record is not a readiness claim; the readiness record that
/// follows is bound to the validated permit, activation receipt, and ready
/// receipt.
///
/// Every value is a handle the caller already holds. A slot the driver does not
/// hold reads `Unavailable`; nothing is invented.
#[cfg(windows)]
fn kernel_activation_readiness_requested_fields<'a>(
    identity: &'a ActivationRecordIdentity<'a>,
    candidate: &'a HostKernelCandidateBinding,
    ready: &'a KernelReadyReceipt,
) -> ActivationIdentityFields<'a> {
    let mut fields = identity.with_candidate();
    fields.push((
        "candidate_activation",
        super::host_job_launch::LaunchIdentityField::Text(candidate.activation_id.as_str()),
    ));
    fields.push((
        "authority_epoch",
        super::host_job_launch::LaunchIdentityField::Number(candidate.kernel_epoch.sequence.get()),
    ));
    fields.push((
        "ready_receipt_activation",
        super::host_job_launch::LaunchIdentityField::Text(ready.activation_id.as_str()),
    ));
    fields.push((
        "ready_receipt_operation",
        super::host_job_launch::LaunchIdentityField::Text(ready.activation_operation_id.as_str()),
    ));
    fields
}

/// Identity slots one readiness/activation observation contributes to a record.
///
/// Everything bound here is held at that point: the committed `Active`
/// append's journal transaction identity and sequence, the permit's operation
/// id and authority epoch, the activation receipt's operation id and journal
/// transaction identity, the ready receipt's activation id, operation id and
/// process, and the count of readiness evidence references it carried. The
/// activation nonce digest and the evidence reference handles themselves stay
/// with the journal record.
#[cfg(windows)]
fn kernel_activation_readiness_observed_fields<'a>(
    identity: &'a ActivationRecordIdentity<'a>,
    active_receipt: &'a AppendReceipt,
    permit: &'a KernelActivationPermit,
    activation_receipt: &'a KernelActivationReceipt,
    ready: &'a KernelReadyReceipt,
) -> ActivationIdentityFields<'a> {
    let mut fields = identity.with_journal_and_candidate(active_receipt);
    fields.push((
        "permit_operation",
        super::host_job_launch::LaunchIdentityField::Text(permit.operation_id.as_str()),
    ));
    fields.push((
        "authority_epoch",
        super::host_job_launch::LaunchIdentityField::Number(permit.authority_epoch.sequence.get()),
    ));
    fields.push((
        "resource_generation",
        super::host_job_launch::LaunchIdentityField::Number(permit.generation.value()),
    ));
    fields.push((
        "receipt_operation",
        super::host_job_launch::LaunchIdentityField::Text(activation_receipt.operation_id.as_str()),
    ));
    fields.push((
        "receipt_journal_transaction",
        super::host_job_launch::LaunchIdentityField::Text(
            activation_receipt.journal_transaction_id.as_str(),
        ),
    ));
    fields.push((
        "receipt_journal_sequence",
        super::host_job_launch::LaunchIdentityField::Number(activation_receipt.journal_sequence),
    ));
    fields.push((
        "ready_activation",
        super::host_job_launch::LaunchIdentityField::Text(ready.activation_id.as_str()),
    ));
    fields.push((
        "ready_operation",
        super::host_job_launch::LaunchIdentityField::Text(ready.activation_operation_id.as_str()),
    ));
    fields.push((
        "ready_process",
        super::host_job_launch::LaunchIdentityField::Text(ready.process.process_id.as_str()),
    ));
    fields.push((
        "ready_evidence_count",
        super::host_job_launch::LaunchIdentityField::Number(ready.evidence_refs.len() as u64),
    ));
    fields
}

/// Stable secret-free name for one activation state.
///
/// A projection of the owner's typed [`KernelActivationState`] discriminant
/// only, so a record names the exact state its transition committed without
/// rendering an enum's `Debug` output. Exhaustive, so a new state forces this
/// to stay in sync; it names a state and grants nothing (I14.20).
#[cfg(windows)]
const fn kernel_activation_state_name(state: KernelActivationState) -> &'static str {
    match state {
        KernelActivationState::Idle => "idle",
        KernelActivationState::ShadowNoAuthority => "shadow_no_authority",
        KernelActivationState::HandoffPrepared => "handoff_prepared",
        KernelActivationState::OldTerminated => "old_terminated",
        KernelActivationState::NonceIssued => "nonce_issued",
        KernelActivationState::Activating => "activating",
        KernelActivationState::Active => "active",
        KernelActivationState::Failed => "failed",
        KernelActivationState::ManualRecovery => "manual_recovery",
    }
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
        // The resumed record is the identity this site holds on entry: its
        // fence, activation identity and generation, current operation id,
        // Kernel generation, approved artifact digest, activation state, and
        // candidate Job binding where one was retained. A resumed activation
        // and a fresh bind of the same activation are therefore
        // distinguishable, which stage order alone could not show.
        // WORK_UNIT_CASE: 978/10 — resume is a subordinate phase observation;
        // no terminal here, the outermost #891 contour owns it.
        kernel_activation_observe_bound(
            "host.kernel-activation resume requested",
            &ActivationRecordIdentity::new(&current).with_candidate(),
        );
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
        // The activation identity and generation, the approved artifact digest,
        // the Kernel generation, and the candidate Job binding are all in hand
        // as arguments at this point, so the request record names the exact
        // candidate being bound. The activation operation id is not yet issued
        // (it is created by the record below), so that slot is explicitly
        // unavailable rather than predicted. The candidate pipe identity and
        // the Host process nonce are never recorded. The candidate root process
        // start identity is rendered into a named local first, so the slot below
        // borrows that binding rather than a temporary that would be dropped at
        // the end of the array expression.
        let candidate_process = format!(
            "{}/{}",
            candidate_job_binding.root_pid, candidate_job_binding.root_start_time_100ns
        );
        let requested = [
            (
                "installation",
                super::host_job_launch::LaunchIdentityField::Text(host.installation.as_str()),
            ),
            (
                "host_epoch",
                super::host_job_launch::LaunchIdentityField::Number(
                    host.epoch.current.sequence.get(),
                ),
            ),
            (
                "activation",
                super::host_job_launch::LaunchIdentityField::Text(activation_id.as_str()),
            ),
            (
                "activation_generation",
                super::host_job_launch::LaunchIdentityField::Number(
                    activation_generation.current.sequence.get(),
                ),
            ),
            (
                "operation",
                super::host_job_launch::LaunchIdentityField::Unavailable,
            ),
            (
                "kernel_generation",
                super::host_job_launch::LaunchIdentityField::Number(
                    kernel_generation.current.sequence.get(),
                ),
            ),
            (
                "artifact_digest",
                super::host_job_launch::LaunchIdentityField::Text(approved_artifact_hash.as_str()),
            ),
            (
                "candidate_job",
                super::host_job_launch::LaunchIdentityField::Text(
                    candidate_job_binding.job_name.as_str(),
                ),
            ),
            (
                "candidate_process",
                super::host_job_launch::LaunchIdentityField::Text(candidate_process.as_str()),
            ),
        ];
        // WORK_UNIT_CASE: 978/7 — candidate bind requested; handshake/auth
        // material is distinct from nonce/activation, no secrets observed.
        kernel_activation_observe_bound("host.kernel-activation bind requested", &requested);
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
        let bound_receipt = append_reconciled(journal, HostStateRecord::Kernel(current.clone()))?;
        // The bound record now carries the issued activation operation id, the
        // committed journal transaction identity and sequence, and the
        // candidate Job binding, so the observed record names the exact
        // durable operation this bind produced.
        // WORK_UNIT_CASE: 978/7 — candidate observed; still distinct from
        // nonce issuance and activation below.
        kernel_activation_observe_bound(
            "host.kernel-activation candidate observed",
            &ActivationRecordIdentity::new(&current).with_journal_and_candidate(&bound_receipt),
        );
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
        let receipt = self.transition(
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
        // The committed append's transaction identity and sequence, and the
        // disposition-evidence count this transition added, are in hand here, so
        // the handoff record names the exact durable boundary. The handoff
        // receipt's own evidence handle stays with the journal record.
        kernel_activation_observe_bound(
            "host.kernel-activation handoff prepared observed",
            &ActivationRecordIdentity::with(
                ActivationRecordIdentity::new(&self.current).with_journal_and_candidate(&receipt),
                "disposition_evidence",
                super::host_job_launch::LaunchIdentityField::Number(
                    self.current.disposition_evidence.len() as u64,
                ),
            ),
        );
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
        let receipt = self.transition(
            KernelActivationState::OldTerminated,
            "kernel-prior-disposition",
            |_| Ok(()),
        )?;
        // The committed append's transaction identity and sequence identify the
        // exact durable prior-disposition commit. Whether a prior contour
        // existed is a real, held distinction here (`recover_retained` proved
        // it above), so it is bound rather than left to stage order.
        kernel_activation_observe_bound(
            "host.kernel-activation prior disposition committed observed",
            &ActivationRecordIdentity::with(
                ActivationRecordIdentity::new(&self.current).with_journal_and_candidate(&receipt),
                "prior_kernel",
                super::host_job_launch::LaunchIdentityField::Text(
                    if matches!(
                        self.current.prior_kernel_disposition,
                        PriorKernelDisposition::NoPriorKernel
                    ) {
                        "none"
                    } else {
                        "present"
                    },
                ),
            ),
        );
        Ok(())
    }

    pub(super) fn issue_nonce(
        &mut self,
        candidate: &HostKernelCandidateBinding,
        generation: ResourceGeneration,
    ) -> Result<KernelActivationPermit, HostError> {
        // The candidate's authority epoch and the resource generation are in
        // hand as arguments, and the current record carries the activation
        // identity, operation id, and candidate Job binding. The one-time nonce
        // value itself is never observed and never predicted.
        // WORK_UNIT_CASE: 978/7 — nonce requested; the nonce value itself is
        // never observed, only this static literal (no secrets).
        kernel_activation_observe_bound(
            "host.kernel-activation nonce requested",
            &ActivationRecordIdentity::with(
                ActivationRecordIdentity::new(&self.current).with_candidate(),
                "authority_epoch",
                super::host_job_launch::LaunchIdentityField::Number(
                    candidate.kernel_epoch.sequence.get(),
                ),
            ),
        );
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
        // The issued permit is in hand and carries the exact operation id, the
        // committed journal transaction identity and sequence, the approved
        // resource generation, and the Kernel authority epoch — plus the
        // candidate and prior-disposition digests, which are non-secret
        // identities the Kernel validates against. The activation nonce inside
        // the permit is never recorded, in raw or digested form.
        // WORK_UNIT_CASE: 978/7 — nonce issued distinctly from handshake/auth
        // and activation; exact permit propagates unchanged.
        kernel_activation_observe_bound(
            "host.kernel-activation nonce issued",
            &[
                ActivationRecordIdentity::new(&self.current)
                    .with_journal(&receipt)
                    .as_slice(),
                [
                    (
                        "authority_epoch",
                        super::host_job_launch::LaunchIdentityField::Number(
                            permit.authority_epoch.sequence.get(),
                        ),
                    ),
                    (
                        "resource_generation",
                        super::host_job_launch::LaunchIdentityField::Number(
                            permit.generation.value(),
                        ),
                    ),
                    (
                        "candidate_digest",
                        super::host_job_launch::LaunchIdentityField::Text(
                            permit.candidate_binding_digest.as_str(),
                        ),
                    ),
                    (
                        "prior_disposition_digest",
                        super::host_job_launch::LaunchIdentityField::Text(
                            permit.prior_kernel_disposition_digest.as_str(),
                        ),
                    ),
                ]
                .as_slice(),
            ]
            .concat(),
        );
        Ok(permit)
    }

    pub(super) fn activating(&mut self) -> Result<(), HostError> {
        // The issued permit, when there is one, is the exact authority under
        // which the Activate is requested, so its operation id, committed
        // journal transaction identity and sequence, and Kernel authority epoch
        // are bound. Before a permit exists there is no such authority, and the
        // slot says so rather than naming a default.
        // WORK_UNIT_CASE: 978/7 — activating requested; forbidden before the
        // committed NonceIssued receipt, distinct from nonce issuance.
        let permit_operation = self.issued_permit.as_ref().map_or(
            super::host_job_launch::LaunchIdentityField::Unavailable,
            |permit| {
                super::host_job_launch::LaunchIdentityField::Text(permit.operation_id.as_str())
            },
        );
        let permit_authority_epoch = self.issued_permit.as_ref().map_or(
            super::host_job_launch::LaunchIdentityField::Unavailable,
            |permit| {
                super::host_job_launch::LaunchIdentityField::Number(
                    permit.authority_epoch.sequence.get(),
                )
            },
        );
        kernel_activation_observe_bound(
            "host.kernel-activation activating requested",
            &ActivationRecordIdentity::with(
                ActivationRecordIdentity::with(
                    ActivationRecordIdentity::new(&self.current).with_candidate(),
                    "permit_operation",
                    permit_operation,
                ),
                "authority_epoch",
                permit_authority_epoch,
            ),
        );
        if self.issued_permit.is_none() {
            return Err(HostError::ProcessContour(
                "Activate is forbidden before a committed NonceIssued receipt".to_owned(),
            ));
        }
        let receipt = self.transition(
            KernelActivationState::Activating,
            "kernel-activating",
            |_| Ok(()),
        )?;
        kernel_activation_observe_bound(
            "host.kernel-activation activating observed",
            &ActivationRecordIdentity::new(&self.current).with_journal_and_candidate(&receipt),
        );
        Ok(())
    }

    pub(super) fn active(
        &mut self,
        candidate: &HostKernelCandidateBinding,
        activation_receipt: &KernelActivationReceipt,
        ready: &KernelReadyReceipt,
    ) -> Result<(), HostError> {
        // This is the only owner-evidence path in the whole Host launch slice
        // that may claim readiness, so the record states the exact identities
        // the evidence will be checked against: the candidate's activation
        // identity, the Kernel authority epoch, the approved resource
        // generation, and the candidate Job binding. A request record is not a
        // readiness claim; the readiness record below follows the validated
        // permit, activation receipt and ready receipt.
        // WORK_UNIT_CASE: 978/8 — readiness requested; positive activation
        // requires actual owner evidence (permit + receipts), never liveness
        // alone.
        kernel_activation_observe_bound(
            "host.kernel-activation readiness requested",
            &kernel_activation_readiness_requested_fields(
                &ActivationRecordIdentity::new(&self.current),
                candidate,
                ready,
            ),
        );
        // I14.16 step 7/8: the candidate must hold exclusive ownership of its
        // own contour before Host publishes it. This runs before the permit,
        // receipt and nonce checks so a candidate that never took the owner
        // object is refused here, not after the stable pipe is committed.
        prove_candidate_owner_held(candidate)?;
        let permit = self.issued_permit.clone().ok_or_else(|| {
            HostError::ProcessContour("active Kernel is missing its issued permit".to_owned())
        })?;
        activation_receipt
            .validate(&permit)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        ready
            .validate(candidate, activation_receipt)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let active_receipt =
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
        // Everything below is held: the committed `Active` append's journal
        // transaction identity and sequence, the permit's operation id and
        // authority epoch, the activation receipt's operation id and journal
        // transaction identity, the ready receipt's activation id, operation id,
        // and the count of readiness evidence references it carried. The
        // activation nonce digest and the evidence reference handles
        // themselves stay with the journal record.
        // The record identity is bound to a named local first, so the slots it
        // projects below borrow that binding for the whole statement instead of
        // a temporary that would be dropped at the end of this `let`. The slots
        // and their order are otherwise exactly what the record already binds.
        let identity = ActivationRecordIdentity::new(&self.current);
        let evidence_fields = kernel_activation_readiness_observed_fields(
            &identity,
            &active_receipt,
            &permit,
            activation_receipt,
            ready,
        );
        // WORK_UNIT_CASE: 978/7 — activation observed distinctly from nonce/
        // handshake/auth; WORK_UNIT_CASE: 978/8 — readiness observed only on
        // exact owner evidence above, exact errors propagate unchanged.
        kernel_activation_observe_bound(
            "host.kernel-activation activation observed",
            &evidence_fields,
        );
        kernel_activation_observe_bound(
            "host.kernel-activation readiness observed",
            &evidence_fields,
        );
        Ok(())
    }

    pub(super) fn fail(&mut self, evidence: &str) -> Result<(), HostError> {
        // The record's identity is the activation this failure belongs to: its
        // fence, activation identity and generation, the operation id in force
        // at the time, the Kernel generation, the approved artifact digest, and
        // the candidate Job/process binding. The state the record was in before
        // this call is a real, held distinction — a first failure and a repeated
        // failure of an already-failed activation are different operations — so
        // it is bound instead of collapsing into one static string. The
        // caller-supplied evidence label is free text that may embed a path, so
        // it stays owner-supplied and is never recorded.
        // WORK_UNIT_CASE: 978/10 — failure observed without owning a terminal;
        // the outermost #891 contour emits the single terminal.
        kernel_activation_observe_bound(
            "host.kernel-activation fail observed",
            &ActivationRecordIdentity::new(&self.current).with_candidate(),
        );
        if self.current.state == KernelActivationState::Failed {
            return Ok(());
        }
        let evidence = PlatformHandle::new(evidence)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let receipt = self.transition(
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
        // The committed failure append's journal transaction identity and
        // sequence identify the exact durable failure record this activation
        // produced, so a failure of activation A is never confused with the
        // same phase of activation B.
        kernel_activation_observe_bound(
            "host.kernel-activation failure committed observed",
            &ActivationRecordIdentity::new(&self.current).with_journal_and_candidate(&receipt),
        );
        Ok(())
    }
}
