use super::{
    AppendReceipt, EpochTransition, HealthDimension, HostError, HostInstallationEpoch,
    HostKernelCandidateBinding, HostStateJournalService, HostStateRecord, JournalBackend,
    KernelActivationPermit, KernelActivationReceipt, KernelActivationState, KernelJobBinding,
    KernelReadyReceipt, KernelRecord, NonceState, OneTimeNonceState, PlatformHandle,
    PriorKernelDisposition, ResourceGeneration, ServiceProcessRecord, ServiceProcessState,
    append_reconciled, fresh_kernel_activation_nonce, nonce_after_activation_failure, operation,
    record_fence, sha256_json,
};

#[cfg(windows)]
pub(super) struct DurableKernelActivationDriver<'a, B: JournalBackend> {
    journal: &'a HostStateJournalService<B>,
    current: KernelRecord,
    issued_permit: Option<KernelActivationPermit>,
}

#[cfg(windows)]
impl<'a, B: JournalBackend> DurableKernelActivationDriver<'a, B> {
    pub(super) fn resume(journal: &'a HostStateJournalService<B>, current: KernelRecord) -> Self {
        Self {
            journal,
            current,
            issued_permit: None,
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
        Ok(Self {
            journal,
            current,
            issued_permit: None,
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

    pub(super) fn handoff_prepared(&mut self) -> Result<(), HostError> {
        self.transition(
            KernelActivationState::HandoffPrepared,
            "kernel-handoff-prepared",
            |_| Ok(()),
        )?;
        Ok(())
    }

    pub(super) fn prior_disposition_committed(&mut self) -> Result<(), HostError> {
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
            authority_epoch: candidate.kernel_epoch,
            activation_nonce: nonce,
        };
        permit
            .validate(candidate, generation)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        self.issued_permit = Some(permit.clone());
        Ok(permit)
    }

    pub(super) fn activating(&mut self) -> Result<(), HostError> {
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
        Ok(())
    }

    pub(super) fn fail(&mut self, evidence: &str) -> Result<(), HostError> {
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
