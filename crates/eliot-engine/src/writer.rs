use crate::{EngineError, resolve_canonical_case_dispositions};
use eliot_store::{CanonicalStore, ControlWal, StoreError, WalWriteState};
use eliot_types::{
    CognitiveRunContract, CognitiveRunTerminal, CognitiveSharedGateBinding, MemoryLifecycleState,
    MemoryStateTransition, MemoryWriteEnvelope, ProjectId, ProjectSequence, SessionId, TaskId,
    WriteId, WriteReceipt, WriteReceiptRef, WriteRejectReason, WriteStatus,
};
use tokio::sync::{mpsc, oneshot};

pub struct WriterRequest {
    pub envelope: MemoryWriteEnvelope,
    pub response_tx: oneshot::Sender<Result<WriteReceipt, EngineError>>,
}

#[derive(Clone, Debug)]
pub struct CognitiveBeginPrecondition {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub run_id: String,
    pub call_number: u8,
    pub contract_receipt: WriteReceiptRef,
    pub previous_terminal_receipt: Option<WriteReceiptRef>,
    pub shared_gate: Option<CognitiveSharedGateBinding>,
}

#[derive(Clone, Debug)]
pub struct CognitiveTerminalPrecondition {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub run_id: String,
    pub call_id: String,
    pub call_number: u8,
    pub session_id: SessionId,
    pub attempt_receipt: WriteReceiptRef,
    pub candidate_receipt: WriteReceiptRef,
    pub expected_write_id: WriteId,
    pub expected_body_sha256: String,
}

enum WriterMessage {
    Write(WriterRequest),
    CognitiveBegin {
        envelope: Box<MemoryWriteEnvelope>,
        precondition: CognitiveBeginPrecondition,
        response_tx: oneshot::Sender<Result<WriteReceipt, EngineError>>,
    },
    CognitiveTerminal {
        envelope: Box<MemoryWriteEnvelope>,
        precondition: CognitiveTerminalPrecondition,
        response_tx: oneshot::Sender<Result<WriteReceipt, EngineError>>,
    },
}

#[derive(Clone, Debug)]
pub struct WriterConfig {
    pub queue_capacity: usize,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 1024,
        }
    }
}

#[derive(Clone)]
pub struct WriterHandle {
    tx: mpsc::Sender<WriterMessage>,
}

pub struct WriterActor {
    wal: ControlWal,
    store: CanonicalStore,
    rx: mpsc::Receiver<WriterMessage>,
}

impl WriterActor {
    pub fn channel(
        wal: ControlWal,
        store: CanonicalStore,
        config: &WriterConfig,
    ) -> (WriterHandle, Self) {
        let (tx, rx) = mpsc::channel(config.queue_capacity);
        (WriterHandle { tx }, Self { wal, store, rx })
    }

    pub async fn run(mut self) {
        while let Some(message) = self.rx.recv().await {
            match message {
                WriterMessage::Write(request) => {
                    let result = self.apply(request.envelope).await;
                    let _ = request.response_tx.send(result);
                }
                WriterMessage::CognitiveBegin {
                    envelope,
                    precondition,
                    response_tx,
                } => {
                    let result = self
                        .validate_cognitive_begin(&precondition)
                        .await
                        .map(|()| envelope);
                    let result = match result {
                        Ok(envelope) => self.apply(*envelope).await,
                        Err(error) => Err(error),
                    };
                    let _ = response_tx.send(result);
                }
                WriterMessage::CognitiveTerminal {
                    envelope,
                    precondition,
                    response_tx,
                } => {
                    let result = self
                        .validate_cognitive_terminal(&precondition)
                        .await
                        .map(|()| envelope);
                    let result = match result {
                        Ok(envelope) => self.apply(*envelope).await,
                        Err(error) => Err(error),
                    };
                    let _ = response_tx.send(result);
                }
            }
        }
    }

    async fn validate_cognitive_terminal(
        &self,
        precondition: &CognitiveTerminalPrecondition,
    ) -> Result<(), EngineError> {
        let receipt = self
            .store
            .write_receipt_by_id(&precondition.candidate_receipt.write_id)
            .await?
            .ok_or_else(|| {
                EngineError::WriteRejected("source candidate receipt disappeared".to_owned())
            })?;
        let claim = self
            .store
            .claim_card_by_id(
                precondition.project_id,
                eliot_types::ClaimId::from_uuid(precondition.expected_write_id.as_uuid()),
            )
            .await?
            .ok_or_else(|| {
                EngineError::WriteRejected("source candidate claim disappeared".to_owned())
            })?;
        if precondition.candidate_receipt.write_id != precondition.expected_write_id
            || receipt.receipt_id != precondition.candidate_receipt.receipt_id
            || receipt.project_id != precondition.project_id
            || receipt.task_id != Some(precondition.task_id)
            || claim.project_id != precondition.project_id
            || claim.task_id != Some(precondition.task_id)
            || claim.write_id != precondition.expected_write_id
            || claim.status != eliot_types::EpistemicStatus::Candidate
            || claim.payload.get("candidate_only") != Some(&serde_json::json!(true))
            || claim.payload.get("profile") != Some(&serde_json::json!("cognitive_child"))
            || claim.payload.get("cognitive_run_id")
                != Some(&serde_json::json!(precondition.run_id))
            || claim.payload.get("cognitive_call_id")
                != Some(&serde_json::json!(precondition.call_id))
            || claim.payload.get("cognitive_call_number")
                != Some(&serde_json::json!(precondition.call_number))
            || claim.payload.get("cognitive_session_id")
                != Some(&serde_json::json!(precondition.session_id))
            || claim.payload.get("cognitive_body_sha256")
                != Some(&serde_json::json!(precondition.expected_body_sha256))
            || claim.payload.get("cognitive_attempt_receipt")
                != Some(&serde_json::json!(precondition.attempt_receipt))
            || claim
                .payload
                .get("statement")
                .and_then(serde_json::Value::as_str)
                != Some(claim.statement.as_str())
        {
            return Err(EngineError::WriteRejected(
                "source candidate claim changed before terminal commit".to_owned(),
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn validate_cognitive_begin(
        &self,
        precondition: &CognitiveBeginPrecondition,
    ) -> Result<(), EngineError> {
        let contract = self
            .store
            .canonical_record_by_write_id::<CognitiveRunContract>(
                precondition.project_id,
                Some(precondition.task_id),
                &["cognitive_run_contract"],
                precondition.contract_receipt.write_id,
            )
            .await?
            .ok_or_else(|| {
                EngineError::WriteRejected("cognitive contract disappeared".to_owned())
            })?;
        if contract.canonical_receipt != precondition.contract_receipt
            || contract.receipt_body.run_id != precondition.run_id
        {
            return Err(EngineError::WriteRejected(
                "cognitive contract precondition differs".to_owned(),
            ));
        }
        match (
            &precondition.previous_terminal_receipt,
            precondition.call_number,
        ) {
            (None, 1) => {}
            (Some(expected), call_number) if call_number > 1 => {
                let terminal = self
                    .store
                    .canonical_record_by_write_id::<CognitiveRunTerminal>(
                        precondition.project_id,
                        Some(precondition.task_id),
                        &["cognitive_run_terminal"],
                        expected.write_id,
                    )
                    .await?
                    .ok_or_else(|| {
                        EngineError::WriteRejected(
                            "cognitive previous terminal disappeared".to_owned(),
                        )
                    })?;
                if terminal.canonical_receipt != *expected
                    || terminal.receipt_body.run_id != precondition.run_id
                    || terminal.receipt_body.call_number + 1 != call_number
                    || terminal.receipt_body.status
                        != eliot_types::CognitiveRunCallStatus::Succeeded
                {
                    return Err(EngineError::WriteRejected(
                        "cognitive previous terminal precondition differs".to_owned(),
                    ));
                }
            }
            _ => {
                return Err(EngineError::WriteRejected(
                    "cognitive previous terminal cardinality differs".to_owned(),
                ));
            }
        }
        if precondition.call_number <= 16 {
            if precondition.shared_gate.is_some() {
                return Err(EngineError::WriteRejected(
                    "cognitive gate is forbidden before call 17".to_owned(),
                ));
            }
            return Ok(());
        }
        let gate = precondition.shared_gate.as_ref().ok_or_else(|| {
            EngineError::WriteRejected("cognitive reciprocal gate is absent".to_owned())
        })?;
        if gate.contract_receipt != precondition.contract_receipt
            || gate.pre_gate_terminal_receipts.len() != 16
            || gate.source_disposition_receipts.len() != 2
            || gate.reciprocal_verification_receipts.len() != 2
            || gate.canonical_case_dispositions.len() != 2
        {
            return Err(EngineError::WriteRejected(
                "cognitive reciprocal gate cardinality differs".to_owned(),
            ));
        }
        let canonical_dispositions = resolve_canonical_case_dispositions(
            &self.store,
            &contract,
            time::OffsetDateTime::now_utc(),
        )
        .await?;
        if gate.canonical_case_dispositions != canonical_dispositions {
            return Err(EngineError::WriteRejected(
                "cognitive reciprocal gate differs from canonical case dispositions".to_owned(),
            ));
        }
        for (index, receipt) in gate.pre_gate_terminal_receipts.iter().enumerate() {
            let terminal = self
                .store
                .canonical_record_by_write_id::<CognitiveRunTerminal>(
                    precondition.project_id,
                    Some(precondition.task_id),
                    &["cognitive_run_terminal"],
                    receipt.write_id,
                )
                .await?
                .ok_or_else(|| {
                    EngineError::WriteRejected("cognitive gate terminal disappeared".to_owned())
                })?;
            if terminal.canonical_receipt != *receipt
                || terminal.receipt_body.run_id != precondition.run_id
                || usize::from(terminal.receipt_body.call_number) != index + 1
                || terminal.receipt_body.status != eliot_types::CognitiveRunCallStatus::Succeeded
                || terminal.receipt_body.raw_verifier_receipts.len() != 1
            {
                return Err(EngineError::WriteRejected(
                    "cognitive gate terminal chain changed".to_owned(),
                ));
            }
            if index == 4
                && terminal.receipt_body.candidate_receipt.as_ref()
                    != gate.reciprocal_verification_receipts.first()
            {
                return Err(EngineError::WriteRejected(
                    "LC-01 gate candidate differs from source terminal".to_owned(),
                ));
            }
            if index == 6
                && terminal.receipt_body.candidate_receipt.as_ref()
                    != gate.reciprocal_verification_receipts.get(1)
            {
                return Err(EngineError::WriteRejected(
                    "LC-02 gate candidate differs from source terminal".to_owned(),
                ));
            }
        }
        let mut promotion_revisions = Vec::with_capacity(2);
        for (index, (candidate, disposition)) in gate
            .reciprocal_verification_receipts
            .iter()
            .zip(&gate.source_disposition_receipts)
            .enumerate()
        {
            let source_terminal_receipt =
                &gate.pre_gate_terminal_receipts[if index == 0 { 4 } else { 6 }];
            let source_terminal = self
                .store
                .canonical_record_by_write_id::<CognitiveRunTerminal>(
                    precondition.project_id,
                    Some(precondition.task_id),
                    &["cognitive_run_terminal"],
                    source_terminal_receipt.write_id,
                )
                .await?
                .ok_or_else(|| {
                    EngineError::WriteRejected("source terminal disappeared".to_owned())
                })?;
            let source_attempt = self
                .store
                .canonical_record_by_write_id::<eliot_types::CognitiveRunAttempt>(
                    precondition.project_id,
                    Some(precondition.task_id),
                    &["cognitive_run_attempt"],
                    source_terminal.receipt_body.attempt_receipt.write_id,
                )
                .await?
                .ok_or_else(|| {
                    EngineError::WriteRejected("source attempt disappeared".to_owned())
                })?;
            let claim = self
                .store
                .claim_card_by_id(
                    precondition.project_id,
                    eliot_types::ClaimId::from_uuid(candidate.write_id.as_uuid()),
                )
                .await?
                .ok_or_else(|| {
                    EngineError::WriteRejected("reciprocal candidate disappeared".to_owned())
                })?;
            let receipt = self
                .store
                .write_receipt_by_id(&disposition.write_id)
                .await?
                .ok_or_else(|| {
                    EngineError::WriteRejected("reciprocal disposition disappeared".to_owned())
                })?;
            let subject_ref = format!("claim:{}", claim.claim_id);
            let latest_lifecycle = self
                .store
                .canonical_records_by_subject_ref::<MemoryStateTransition>(
                    precondition.project_id,
                    Some(precondition.task_id),
                    &["state_transition"],
                    &subject_ref,
                    1,
                )
                .await?
                .into_iter()
                .next();
            let lifecycle_state = latest_lifecycle.map_or(MemoryLifecycleState::Active, |record| {
                record.receipt_body.to_state
            });
            if claim.status != eliot_types::EpistemicStatus::Verified
                || claim.write_id != disposition.write_id
                || receipt.receipt_id != disposition.receipt_id
                || receipt.project_id != precondition.project_id
                || receipt.task_id != Some(precondition.task_id)
                || claim.payload.get("cognitive_run_id")
                    != Some(&serde_json::json!(precondition.run_id))
                || claim.payload.get("cognitive_call_id")
                    != Some(&serde_json::json!(source_attempt.receipt_body.call_id))
                || claim.payload.get("cognitive_call_number")
                    != Some(&serde_json::json!(source_attempt.receipt_body.call_number))
                || claim.payload.get("cognitive_attempt_receipt")
                    != Some(&serde_json::json!(source_attempt.canonical_receipt))
                || !matches!(
                    lifecycle_state,
                    MemoryLifecycleState::Active | MemoryLifecycleState::Restored
                )
            {
                return Err(EngineError::WriteRejected(
                    "reciprocal candidate lifecycle changed before begin".to_owned(),
                ));
            }
            promotion_revisions.push((receipt.memory_revision, disposition));
        }
        promotion_revisions.sort_by_key(|(revision, _)| *revision);
        if promotion_revisions[0].0 == promotion_revisions[1].0
            || promotion_revisions[1]
                .0
                .map(eliot_types::MemoryRevision::value)
                != Some(gate.gate_revision)
            || promotion_revisions[1].1 != &gate.gate_receipt
        {
            return Err(EngineError::WriteRejected(
                "reciprocal gate latest promotion changed before begin".to_owned(),
            ));
        }
        Ok(())
    }

    async fn apply(&self, mut envelope: MemoryWriteEnvelope) -> Result<WriteReceipt, EngineError> {
        let boundary_bytes = serde_json::to_vec(&envelope)?;
        if let Err(violation) = eliot_types::inspect_secret_bytes(&boundary_bytes) {
            return Err(EngineError::WriteRejected(format!(
                "secret boundary rejected memory ingress: {}",
                violation.rule
            )));
        }
        if envelope.input_hash.trim().is_empty() {
            return Err(EngineError::WriteRejected(
                "input_hash is required".to_owned(),
            ));
        }

        if let Some(existing) = self.wal.get_by_write_id(&envelope.write_id)? {
            match existing {
                WalWriteState::Committed(receipt) if receipt.input_hash == envelope.input_hash => {
                    return Ok(*receipt);
                }
                WalWriteState::Committed(_) => {
                    return Err(EngineError::WriteRejected(
                        "write_id idempotency conflict".to_owned(),
                    ));
                }
                WalWriteState::Pending(pending)
                    if pending.envelope.input_hash == envelope.input_hash =>
                {
                    envelope = pending.envelope;
                }
                WalWriteState::Pending(_) => {
                    return Err(EngineError::WriteRejected(
                        "write_id pending idempotency conflict".to_owned(),
                    ));
                }
                WalWriteState::Failed(_) | WalWriteState::DeadLetter(_) => {
                    return Err(EngineError::WriteRejected(
                        "write_id already failed".to_owned(),
                    ));
                }
            }
        }

        if envelope.project_sequence_hint.is_none() {
            envelope.project_sequence_hint = Some(self.next_project_sequence(envelope.project_id)?);
        }

        if self.wal.get_by_write_id(&envelope.write_id)?.is_none() {
            self.wal.append_pending(&envelope)?;
        }

        self.wal.mark_applying(&envelope.write_id)?;

        match self.store.apply_write_envelope(&envelope).await {
            Ok(receipt) => self.handle_store_receipt(receipt),
            Err(error) => {
                if is_ambiguous_commit_error(&error) {
                    return self.reconcile_unknown_commit(&envelope, error).await;
                }
                self.wal.mark_failed(&envelope.write_id, &error)?;
                Err(error.into())
            }
        }
    }

    fn handle_store_receipt(&self, receipt: WriteReceipt) -> Result<WriteReceipt, EngineError> {
        if receipt.status == WriteStatus::Rejected {
            self.wal.mark_rejected(&receipt)?;
            let reason = receipt.rejected_reason.map_or_else(
                || "write rejected".to_owned(),
                |reason| format!("{reason:?}"),
            );
            return Err(EngineError::WriteRejected(reason));
        }
        self.wal.mark_committed(&receipt)?;
        Ok(receipt)
    }

    async fn reconcile_unknown_commit(
        &self,
        envelope: &MemoryWriteEnvelope,
        error: StoreError,
    ) -> Result<WriteReceipt, EngineError> {
        self.wal.mark_unknown_commit(&envelope.write_id, &error)?;
        if let Some(receipt) = self.store.write_receipt_by_id(&envelope.write_id).await? {
            if receipt.input_hash == envelope.input_hash {
                self.wal.mark_committed(&receipt)?;
                return Ok(receipt);
            }
            let rejected =
                conflict_receipt(envelope, receipt.memory_revision, receipt.project_sequence);
            self.wal.mark_rejected(&rejected)?;
            return Err(EngineError::WriteRejected(
                "unknown commit reconciled to input hash conflict".to_owned(),
            ));
        }

        match self.store.apply_write_envelope(envelope).await {
            Ok(receipt) => self.handle_store_receipt(receipt),
            Err(retry_error) => {
                self.wal
                    .move_to_dead_letter(&envelope.write_id, &retry_error.to_string())?;
                Err(retry_error.into())
            }
        }
    }

    fn next_project_sequence(
        &self,
        project_id: eliot_types::ProjectId,
    ) -> Result<ProjectSequence, EngineError> {
        let next = self
            .wal
            .project_heads()?
            .into_iter()
            .filter(|head| head.project_id == project_id)
            .map(|head| head.project_sequence.value())
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        Ok(ProjectSequence::new(next))
    }
}

fn is_ambiguous_commit_error(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::Timeout { .. } | StoreError::ConnectionClosed | StoreError::WebSocket(_)
    )
}

fn conflict_receipt(
    envelope: &MemoryWriteEnvelope,
    memory_revision: Option<eliot_types::MemoryRevision>,
    project_sequence: Option<ProjectSequence>,
) -> WriteReceipt {
    WriteReceipt {
        receipt_id: eliot_types::ReceiptId::from_uuid(envelope.write_id.as_uuid()),
        write_id: envelope.write_id,
        input_hash: envelope.input_hash.clone(),
        project_id: envelope.project_id,
        task_id: envelope.task_id,
        command_kind: envelope.command_kind,
        status: WriteStatus::Rejected,
        memory_revision,
        project_sequence,
        created_records: Vec::new(),
        created_relations: Vec::new(),
        weak_records: Vec::new(),
        rejected_reason: Some(WriteRejectReason::WriteIdInputHashConflict),
        db_operation_id: Some(envelope.operation_id),
        created_at: time::OffsetDateTime::now_utc(),
    }
}

impl WriterHandle {
    pub async fn submit(&self, envelope: MemoryWriteEnvelope) -> Result<WriteReceipt, EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        let request = WriterRequest {
            envelope,
            response_tx,
        };
        self.tx
            .try_send(WriterMessage::Write(request))
            .map_err(|_| EngineError::Backpressure)?;
        response_rx.await.map_err(|_| EngineError::WriterClosed)?
    }

    pub async fn submit_cognitive_begin(
        &self,
        envelope: MemoryWriteEnvelope,
        precondition: CognitiveBeginPrecondition,
    ) -> Result<WriteReceipt, EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .try_send(WriterMessage::CognitiveBegin {
                envelope: Box::new(envelope),
                precondition,
                response_tx,
            })
            .map_err(|_| EngineError::Backpressure)?;
        response_rx.await.map_err(|_| EngineError::WriterClosed)?
    }

    pub async fn submit_cognitive_terminal(
        &self,
        envelope: MemoryWriteEnvelope,
        precondition: CognitiveTerminalPrecondition,
    ) -> Result<WriteReceipt, EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .try_send(WriterMessage::CognitiveTerminal {
                envelope: Box::new(envelope),
                precondition,
                response_tx,
            })
            .map_err(|_| EngineError::Backpressure)?;
        response_rx.await.map_err(|_| EngineError::WriterClosed)?
    }
}
