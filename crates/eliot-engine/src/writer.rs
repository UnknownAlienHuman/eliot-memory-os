use crate::{
    EngineError, cognitive_projection::CognitiveProjectionCoordinatorHandle,
    resolve_canonical_case_dispositions,
};
use eliot_store::{CanonicalStore, ControlWal, StoreError, WalPendingWrite, WalWriteState};
use eliot_types::{
    CognitiveRunContract, CognitiveRunTerminal, CognitiveSharedGateBinding, MemoryLifecycleState,
    MemoryStateTransition, MemoryWriteEnvelope, ObservabilityWriteEnvelope,
    ObservabilityWriteReceipt, ObservabilityWriteStatus, OperationRestartWindow,
    OperationRuntimeCheckpoint, ProjectId, ProjectRevisionSummary, ProjectSequence,
    SealStagingCheckpoint, SessionId, TaskId, WriteId, WriteReceipt, WriteReceiptRef,
    WriteRejectReason, WriteStatus,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, sleep};

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
    Observability {
        envelope: ObservabilityWriteEnvelope,
        response_tx: oneshot::Sender<Result<ObservabilityWriteReceipt, EngineError>>,
    },
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

impl WriterMessage {
    fn project_id(&self) -> ProjectId {
        match self {
            Self::Write(request) => request.envelope.project_id,
            Self::Observability { envelope, .. } => envelope.project_id,
            Self::CognitiveBegin { envelope, .. } | Self::CognitiveTerminal { envelope, .. } => {
                envelope.project_id
            }
        }
    }

    fn write_id(&self) -> WriteId {
        match self {
            Self::Write(request) => request.envelope.write_id,
            Self::Observability { envelope, .. } => envelope.write_id,
            Self::CognitiveBegin { envelope, .. } | Self::CognitiveTerminal { envelope, .. } => {
                envelope.write_id
            }
        }
    }

    fn reject(self, error: EngineError) {
        match self {
            Self::Write(request) => {
                let _ = request.response_tx.send(Err(error));
            }
            Self::Observability { response_tx, .. } => {
                let _ = response_tx.send(Err(error));
            }
            Self::CognitiveBegin { response_tx, .. }
            | Self::CognitiveTerminal { response_tx, .. } => {
                let _ = response_tx.send(Err(error));
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct WriterConfig {
    pub queue_capacity: usize,
    pub lane_count: usize,
    pub control_wal_queue_capacity: usize,
    pub control_wal_staging_batch_size: usize,
    pub unknown_commit_retry_limit: u8,
    pub unknown_commit_retry_delay: Duration,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 1024,
            lane_count: default_writer_lane_count(),
            control_wal_queue_capacity: 256,
            control_wal_staging_batch_size: 32,
            unknown_commit_retry_limit: 1,
            unknown_commit_retry_delay: Duration::from_millis(25),
        }
    }
}

pub fn default_writer_lane_count() -> usize {
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .clamp(1, 4)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WriterMetricsSnapshot {
    pub configured_lanes: usize,
    pub in_flight_projects: usize,
    pub max_in_flight_projects: usize,
    pub accepted_messages: u64,
    pub rejected_backpressure: u64,
    pub scheduled_retries: u64,
    pub paused_projects: usize,
}

#[derive(Debug)]
struct WriterRuntimeMetrics {
    configured_lanes: usize,
    in_flight_projects: AtomicUsize,
    max_in_flight_projects: AtomicUsize,
    accepted_messages: AtomicU64,
    rejected_backpressure: AtomicU64,
    scheduled_retries: AtomicU64,
    paused_projects: AtomicUsize,
}

impl WriterRuntimeMetrics {
    fn new(configured_lanes: usize) -> Self {
        Self {
            configured_lanes,
            in_flight_projects: AtomicUsize::new(0),
            max_in_flight_projects: AtomicUsize::new(0),
            accepted_messages: AtomicU64::new(0),
            rejected_backpressure: AtomicU64::new(0),
            scheduled_retries: AtomicU64::new(0),
            paused_projects: AtomicUsize::new(0),
        }
    }

    fn project_started(&self) {
        let current = self.in_flight_projects.fetch_add(1, Ordering::Relaxed) + 1;
        self.max_in_flight_projects
            .fetch_max(current, Ordering::Relaxed);
    }

    fn project_finished(&self) {
        self.in_flight_projects.fetch_sub(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> WriterMetricsSnapshot {
        WriterMetricsSnapshot {
            configured_lanes: self.configured_lanes,
            in_flight_projects: self.in_flight_projects.load(Ordering::Relaxed),
            max_in_flight_projects: self.max_in_flight_projects.load(Ordering::Relaxed),
            accepted_messages: self.accepted_messages.load(Ordering::Relaxed),
            rejected_backpressure: self.rejected_backpressure.load(Ordering::Relaxed),
            scheduled_retries: self.scheduled_retries.load(Ordering::Relaxed),
            paused_projects: self.paused_projects.load(Ordering::Relaxed),
        }
    }
}

enum ControlWalMessage {
    GetByWriteId {
        write_id: WriteId,
        response_tx: oneshot::Sender<Result<Option<WalWriteState>, String>>,
    },
    StagePending {
        envelope: MemoryWriteEnvelope,
        response_tx: oneshot::Sender<Result<Option<WalWriteState>, String>>,
    },
    MarkApplying {
        write_id: WriteId,
        response_tx: oneshot::Sender<Result<(), String>>,
    },
    MarkCommitted {
        receipt: WriteReceipt,
        response_tx: oneshot::Sender<Result<(), String>>,
    },
    MarkFailed {
        write_id: WriteId,
        error: String,
        response_tx: oneshot::Sender<Result<(), String>>,
    },
    MarkRejected {
        receipt: WriteReceipt,
        response_tx: oneshot::Sender<Result<(), String>>,
    },
    MarkUnknownCommit {
        write_id: WriteId,
        error: String,
        response_tx: oneshot::Sender<Result<(), String>>,
    },
    MarkRetryable {
        write_id: WriteId,
        error: String,
        response_tx: oneshot::Sender<Result<(), String>>,
    },
    MoveToDeadLetter {
        write_id: WriteId,
        reason: String,
        response_tx: oneshot::Sender<Result<(), String>>,
    },
    ProjectHeads {
        response_tx: oneshot::Sender<Result<Vec<ProjectRevisionSummary>, String>>,
    },
    PutOperationCheckpoint {
        checkpoint: OperationRuntimeCheckpoint,
        response_tx: oneshot::Sender<Result<(), String>>,
    },
    GetOperationCheckpoint {
        operation_id: String,
        response_tx: oneshot::Sender<Result<Option<OperationRuntimeCheckpoint>, String>>,
    },
    ListNonterminalOperationCheckpoints {
        response_tx: oneshot::Sender<Result<Vec<OperationRuntimeCheckpoint>, String>>,
    },
    DeleteTerminalOperationCheckpoint {
        operation_id: String,
        response_tx: oneshot::Sender<Result<bool, String>>,
    },
    LoadRestartWindow {
        key: String,
        response_tx: oneshot::Sender<Result<Option<OperationRestartWindow>, String>>,
    },
    PutRestartWindow {
        window: OperationRestartWindow,
        response_tx: oneshot::Sender<Result<(), String>>,
    },
    PutSealStagingCheckpoint {
        checkpoint: SealStagingCheckpoint,
        response_tx: oneshot::Sender<Result<(), String>>,
    },
    LoadIncompleteSealStaging {
        response_tx: oneshot::Sender<Result<Vec<SealStagingCheckpoint>, String>>,
    },
    RemoveSealStagingCheckpoint {
        seal_attempt_id: String,
        response_tx: oneshot::Sender<Result<bool, String>>,
    },
    GetSupervisionRecoveryCursor {
        response_tx: oneshot::Sender<Result<Option<String>, String>>,
    },
    PutSupervisionRecoveryCursor {
        cursor: String,
        response_tx: oneshot::Sender<Result<(), String>>,
    },
}

#[derive(Clone)]
struct ControlWalHandle {
    tx: mpsc::Sender<ControlWalMessage>,
}

/// The sole owner of the redb control WAL.
///
/// Every operation is intentionally short. Consecutive staging messages are
/// grouped into one bounded redb transaction; `SurrealDB` I/O remains in lane
/// workers and can never extend a redb writer transaction.
pub struct ControlWalActor {
    wal: ControlWal,
    rx: mpsc::Receiver<ControlWalMessage>,
    shutdown_rx: Option<oneshot::Receiver<()>>,
    staging_batch_size: usize,
}

impl ControlWalActor {
    fn channel(
        wal: ControlWal,
        queue_capacity: usize,
        staging_batch_size: usize,
    ) -> (ControlWalHandle, Self) {
        Self::channel_inner(wal, queue_capacity, staging_batch_size, None)
    }

    fn channel_inner(
        wal: ControlWal,
        queue_capacity: usize,
        staging_batch_size: usize,
        shutdown_rx: Option<oneshot::Receiver<()>>,
    ) -> (ControlWalHandle, Self) {
        let (tx, rx) = mpsc::channel(queue_capacity.max(1));
        (
            ControlWalHandle { tx },
            Self {
                wal,
                rx,
                shutdown_rx,
                staging_batch_size: staging_batch_size.max(1),
            },
        )
    }

    #[allow(clippy::too_many_lines)]
    async fn run(mut self) {
        let mut deferred = VecDeque::new();
        let mut shutdown = self.shutdown_rx.take();
        let mut shutdown_armed = shutdown.is_some();
        loop {
            let message = if let Some(message) = deferred.pop_front() {
                Some(message)
            } else {
                tokio::select! {
                    biased;
                    () = async {
                        if let Some(receiver) = shutdown.as_mut() {
                            let _ = receiver.await;
                        }
                    }, if shutdown_armed => {
                        self.rx.close();
                        shutdown_armed = false;
                        self.rx.recv().await
                    }
                    message = self.rx.recv() => message,
                }
            };
            let Some(message) = message else {
                break;
            };
            match message {
                ControlWalMessage::StagePending {
                    envelope,
                    response_tx,
                } => {
                    let mut batch = vec![(envelope, response_tx)];
                    while batch.len() < self.staging_batch_size {
                        match self.rx.try_recv() {
                            Ok(ControlWalMessage::StagePending {
                                envelope,
                                response_tx,
                            }) => batch.push((envelope, response_tx)),
                            Ok(other) => {
                                deferred.push_back(other);
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                    let mut new_envelopes = Vec::new();
                    let mut batch_pending = HashMap::<WriteId, MemoryWriteEnvelope>::new();
                    let mut outcomes = Vec::with_capacity(batch.len());
                    for (envelope, _) in &batch {
                        let outcome = if let Some(first) = batch_pending.get(&envelope.write_id) {
                            Ok(Some(WalWriteState::Pending(Box::new(WalPendingWrite {
                                envelope: first.clone(),
                                status: WriteStatus::Staged,
                                attempts: 0,
                                last_error: None,
                            }))))
                        } else {
                            match self.wal.get_by_write_id(&envelope.write_id) {
                                Ok(Some(existing)) => Ok(Some(existing)),
                                Ok(None) => {
                                    batch_pending.insert(envelope.write_id, envelope.clone());
                                    new_envelopes.push(envelope.clone());
                                    Ok(None)
                                }
                                Err(error) => Err(error.to_string()),
                            }
                        };
                        outcomes.push(outcome);
                    }
                    let stage_error = self
                        .wal
                        .append_pending_batch(&new_envelopes)
                        .err()
                        .map(|error| error.to_string());
                    for ((_, response_tx), outcome) in batch.into_iter().zip(outcomes) {
                        let response = if outcome.as_ref().is_ok_and(std::option::Option::is_none) {
                            stage_error.clone().map_or(Ok(None), Err)
                        } else {
                            outcome
                        };
                        let _ = response_tx.send(response);
                    }
                }
                ControlWalMessage::GetByWriteId {
                    write_id,
                    response_tx,
                } => {
                    let _ = response_tx.send(
                        self.wal
                            .get_by_write_id(&write_id)
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::MarkApplying {
                    write_id,
                    response_tx,
                } => {
                    let _ = response_tx.send(
                        self.wal
                            .mark_applying(&write_id)
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::MarkCommitted {
                    receipt,
                    response_tx,
                } => {
                    let _ = response_tx.send(
                        self.wal
                            .mark_committed(&receipt)
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::MarkFailed {
                    write_id,
                    error,
                    response_tx,
                } => {
                    let _ = response_tx.send(
                        self.wal
                            .mark_failed_message(&write_id, error)
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::MarkRejected {
                    receipt,
                    response_tx,
                } => {
                    let _ = response_tx.send(
                        self.wal
                            .mark_rejected(&receipt)
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::MarkUnknownCommit {
                    write_id,
                    error,
                    response_tx,
                } => {
                    let _ = response_tx.send(
                        self.wal
                            .mark_unknown_commit_message(&write_id, error)
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::MarkRetryable {
                    write_id,
                    error,
                    response_tx,
                } => {
                    let _ = response_tx.send(
                        self.wal
                            .mark_retryable_message(&write_id, error)
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::MoveToDeadLetter {
                    write_id,
                    reason,
                    response_tx,
                } => {
                    let _ = response_tx.send(
                        self.wal
                            .move_to_dead_letter(&write_id, &reason)
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::ProjectHeads { response_tx } => {
                    let _ = response_tx
                        .send(self.wal.project_heads().map_err(|error| error.to_string()));
                }
                ControlWalMessage::PutOperationCheckpoint {
                    checkpoint,
                    response_tx,
                } => {
                    let _ = response_tx.send(
                        self.wal
                            .put_operation_checkpoint(&checkpoint)
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::GetOperationCheckpoint {
                    operation_id,
                    response_tx,
                } => {
                    let _ = response_tx.send(
                        self.wal
                            .get_operation_checkpoint(&operation_id)
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::ListNonterminalOperationCheckpoints { response_tx } => {
                    let _ = response_tx.send(
                        self.wal
                            .list_nonterminal_operation_checkpoints()
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::DeleteTerminalOperationCheckpoint {
                    operation_id,
                    response_tx,
                } => {
                    let _ = response_tx.send(
                        self.wal
                            .delete_terminal_operation_checkpoint_after_retention(&operation_id)
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::LoadRestartWindow { key, response_tx } => {
                    let _ = response_tx.send(
                        self.wal
                            .load_restart_window(&key)
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::PutRestartWindow {
                    window,
                    response_tx,
                } => {
                    let _ = response_tx.send(
                        self.wal
                            .record_restart(&window)
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::PutSealStagingCheckpoint {
                    checkpoint,
                    response_tx,
                } => {
                    let _ = response_tx.send(
                        self.wal
                            .put_seal_staging_checkpoint(&checkpoint)
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::LoadIncompleteSealStaging { response_tx } => {
                    let _ = response_tx.send(
                        self.wal
                            .load_incomplete_seal_staging()
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::RemoveSealStagingCheckpoint {
                    seal_attempt_id,
                    response_tx,
                } => {
                    let _ = response_tx.send(
                        self.wal
                            .complete_or_remove_seal_staging_checkpoint(&seal_attempt_id)
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::GetSupervisionRecoveryCursor { response_tx } => {
                    let _ = response_tx.send(
                        self.wal
                            .supervision_recovery_cursor()
                            .map_err(|error| error.to_string()),
                    );
                }
                ControlWalMessage::PutSupervisionRecoveryCursor {
                    cursor,
                    response_tx,
                } => {
                    let _ = response_tx.send(
                        self.wal
                            .put_supervision_recovery_cursor(&cursor)
                            .map_err(|error| error.to_string()),
                    );
                }
            }
        }
    }
}

impl ControlWalHandle {
    async fn response<T>(
        response_rx: oneshot::Receiver<Result<T, String>>,
    ) -> Result<T, EngineError> {
        response_rx
            .await
            .map_err(|_| EngineError::WriterClosed)?
            .map_err(|reason| EngineError::ServiceNotReady {
                service: "control-wal".to_owned(),
                reason,
            })
    }

    async fn get_by_write_id(
        &self,
        write_id: WriteId,
    ) -> Result<Option<WalWriteState>, EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(ControlWalMessage::GetByWriteId {
                write_id,
                response_tx,
            })
            .await
            .map_err(|_| EngineError::WriterClosed)?;
        Self::response(response_rx).await
    }

    async fn stage_pending(
        &self,
        envelope: MemoryWriteEnvelope,
    ) -> Result<Option<WalWriteState>, EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(ControlWalMessage::StagePending {
                envelope,
                response_tx,
            })
            .await
            .map_err(|_| EngineError::WriterClosed)?;
        Self::response(response_rx).await
    }

    async fn mark_applying(&self, write_id: WriteId) -> Result<(), EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(ControlWalMessage::MarkApplying {
                write_id,
                response_tx,
            })
            .await
            .map_err(|_| EngineError::WriterClosed)?;
        Self::response(response_rx).await
    }

    async fn mark_committed(&self, receipt: WriteReceipt) -> Result<(), EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(ControlWalMessage::MarkCommitted {
                receipt,
                response_tx,
            })
            .await
            .map_err(|_| EngineError::WriterClosed)?;
        Self::response(response_rx).await
    }

    async fn mark_failed(&self, write_id: WriteId, error: String) -> Result<(), EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(ControlWalMessage::MarkFailed {
                write_id,
                error,
                response_tx,
            })
            .await
            .map_err(|_| EngineError::WriterClosed)?;
        Self::response(response_rx).await
    }

    async fn mark_rejected(&self, receipt: WriteReceipt) -> Result<(), EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(ControlWalMessage::MarkRejected {
                receipt,
                response_tx,
            })
            .await
            .map_err(|_| EngineError::WriterClosed)?;
        Self::response(response_rx).await
    }

    async fn mark_unknown_commit(
        &self,
        write_id: WriteId,
        error: String,
    ) -> Result<(), EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(ControlWalMessage::MarkUnknownCommit {
                write_id,
                error,
                response_tx,
            })
            .await
            .map_err(|_| EngineError::WriterClosed)?;
        Self::response(response_rx).await
    }

    async fn mark_retryable(&self, write_id: WriteId, error: String) -> Result<(), EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(ControlWalMessage::MarkRetryable {
                write_id,
                error,
                response_tx,
            })
            .await
            .map_err(|_| EngineError::WriterClosed)?;
        Self::response(response_rx).await
    }

    async fn move_to_dead_letter(
        &self,
        write_id: WriteId,
        reason: String,
    ) -> Result<(), EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(ControlWalMessage::MoveToDeadLetter {
                write_id,
                reason,
                response_tx,
            })
            .await
            .map_err(|_| EngineError::WriterClosed)?;
        Self::response(response_rx).await
    }

    async fn project_heads(&self) -> Result<Vec<ProjectRevisionSummary>, EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(ControlWalMessage::ProjectHeads { response_tx })
            .await
            .map_err(|_| EngineError::WriterClosed)?;
        Self::response(response_rx).await
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "operation", content = "payload")]
#[allow(
    clippy::large_enum_variant,
    reason = "the authenticated IPC wire schema intentionally carries typed runtime records inline"
)]
pub enum OperationRuntimeRequest {
    PutCheckpoint(OperationRuntimeCheckpoint),
    GetCheckpoint(String),
    ListNonterminalCheckpoints,
    DeleteTerminalCheckpoint(String),
    LoadRestartWindow(String),
    PutRestartWindow(OperationRestartWindow),
    PutSealStaging(SealStagingCheckpoint),
    LoadIncompleteSealStaging,
    RemoveSealStaging(String),
    GetRecoveryCursor,
    PutRecoveryCursor(String),
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "result", content = "payload")]
#[allow(
    clippy::large_enum_variant,
    reason = "the authenticated IPC wire schema intentionally carries typed runtime records inline"
)]
pub enum OperationRuntimeResponse {
    Unit,
    Checkpoint(Option<OperationRuntimeCheckpoint>),
    Checkpoints(Vec<OperationRuntimeCheckpoint>),
    Bool(bool),
    RestartWindow(Option<OperationRestartWindow>),
    SealStaging(Vec<SealStagingCheckpoint>),
    Cursor(Option<String>),
}

pub trait OperationRuntimeProxy: Send + Sync {
    fn request(
        &self,
        request: OperationRuntimeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<OperationRuntimeResponse, EngineError>> + Send + '_>>;
}

#[derive(Clone, Default)]
pub struct OperationRuntimeHandle {
    wal: Option<ControlWalHandle>,
    proxy: Option<Arc<dyn OperationRuntimeProxy>>,
}

impl OperationRuntimeHandle {
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            wal: None,
            proxy: None,
        }
    }

    #[must_use]
    pub fn from_proxy(proxy: Arc<dyn OperationRuntimeProxy>) -> Self {
        Self {
            wal: None,
            proxy: Some(proxy),
        }
    }

    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.wal.is_some() || self.proxy.is_some()
    }

    pub async fn put_checkpoint(
        &self,
        checkpoint: OperationRuntimeCheckpoint,
    ) -> Result<(), EngineError> {
        match self
            .request(OperationRuntimeRequest::PutCheckpoint(checkpoint))
            .await?
        {
            OperationRuntimeResponse::Unit => Ok(()),
            response => Err(unexpected_runtime_response(response)),
        }
    }

    pub async fn get_checkpoint(
        &self,
        operation_id: impl Into<String>,
    ) -> Result<Option<OperationRuntimeCheckpoint>, EngineError> {
        match self
            .request(OperationRuntimeRequest::GetCheckpoint(operation_id.into()))
            .await?
        {
            OperationRuntimeResponse::Checkpoint(checkpoint) => Ok(checkpoint),
            response => Err(unexpected_runtime_response(response)),
        }
    }

    pub async fn list_nonterminal_checkpoints(
        &self,
    ) -> Result<Vec<OperationRuntimeCheckpoint>, EngineError> {
        match self
            .request(OperationRuntimeRequest::ListNonterminalCheckpoints)
            .await?
        {
            OperationRuntimeResponse::Checkpoints(checkpoints) => Ok(checkpoints),
            response => Err(unexpected_runtime_response(response)),
        }
    }

    pub async fn delete_terminal_checkpoint(
        &self,
        operation_id: impl Into<String>,
    ) -> Result<bool, EngineError> {
        match self
            .request(OperationRuntimeRequest::DeleteTerminalCheckpoint(
                operation_id.into(),
            ))
            .await?
        {
            OperationRuntimeResponse::Bool(removed) => Ok(removed),
            response => Err(unexpected_runtime_response(response)),
        }
    }

    pub async fn load_restart_window(
        &self,
        key: impl Into<String>,
    ) -> Result<Option<OperationRestartWindow>, EngineError> {
        match self
            .request(OperationRuntimeRequest::LoadRestartWindow(key.into()))
            .await?
        {
            OperationRuntimeResponse::RestartWindow(window) => Ok(window),
            response => Err(unexpected_runtime_response(response)),
        }
    }

    pub async fn put_restart_window(
        &self,
        window: OperationRestartWindow,
    ) -> Result<(), EngineError> {
        match self
            .request(OperationRuntimeRequest::PutRestartWindow(window))
            .await?
        {
            OperationRuntimeResponse::Unit => Ok(()),
            response => Err(unexpected_runtime_response(response)),
        }
    }

    pub async fn put_seal_staging(
        &self,
        checkpoint: SealStagingCheckpoint,
    ) -> Result<(), EngineError> {
        match self
            .request(OperationRuntimeRequest::PutSealStaging(checkpoint))
            .await?
        {
            OperationRuntimeResponse::Unit => Ok(()),
            response => Err(unexpected_runtime_response(response)),
        }
    }

    pub async fn load_incomplete_seal_staging(
        &self,
    ) -> Result<Vec<SealStagingCheckpoint>, EngineError> {
        match self
            .request(OperationRuntimeRequest::LoadIncompleteSealStaging)
            .await?
        {
            OperationRuntimeResponse::SealStaging(checkpoints) => Ok(checkpoints),
            response => Err(unexpected_runtime_response(response)),
        }
    }

    pub async fn remove_seal_staging(
        &self,
        seal_attempt_id: impl Into<String>,
    ) -> Result<bool, EngineError> {
        match self
            .request(OperationRuntimeRequest::RemoveSealStaging(
                seal_attempt_id.into(),
            ))
            .await?
        {
            OperationRuntimeResponse::Bool(removed) => Ok(removed),
            response => Err(unexpected_runtime_response(response)),
        }
    }

    pub async fn recovery_cursor(&self) -> Result<Option<String>, EngineError> {
        match self
            .request(OperationRuntimeRequest::GetRecoveryCursor)
            .await?
        {
            OperationRuntimeResponse::Cursor(cursor) => Ok(cursor),
            response => Err(unexpected_runtime_response(response)),
        }
    }

    pub async fn put_recovery_cursor(&self, cursor: impl Into<String>) -> Result<(), EngineError> {
        match self
            .request(OperationRuntimeRequest::PutRecoveryCursor(cursor.into()))
            .await?
        {
            OperationRuntimeResponse::Unit => Ok(()),
            response => Err(unexpected_runtime_response(response)),
        }
    }

    pub async fn dispatch_proxy_request(
        &self,
        request: OperationRuntimeRequest,
    ) -> Result<OperationRuntimeResponse, EngineError> {
        self.request(request).await
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the match is the exhaustive typed WAL request dispatcher"
    )]
    async fn request(
        &self,
        request: OperationRuntimeRequest,
    ) -> Result<OperationRuntimeResponse, EngineError> {
        if let Some(proxy) = &self.proxy {
            return proxy.request(request).await;
        }
        let Some(wal) = &self.wal else {
            return Ok(disabled_runtime_response(&request));
        };
        match request {
            OperationRuntimeRequest::PutCheckpoint(checkpoint) => {
                let (response_tx, response_rx) = oneshot::channel();
                wal.tx
                    .send(ControlWalMessage::PutOperationCheckpoint {
                        checkpoint,
                        response_tx,
                    })
                    .await
                    .map_err(|_| EngineError::WriterClosed)?;
                ControlWalHandle::response(response_rx).await?;
                Ok(OperationRuntimeResponse::Unit)
            }
            OperationRuntimeRequest::GetCheckpoint(operation_id) => {
                let (response_tx, response_rx) = oneshot::channel();
                wal.tx
                    .send(ControlWalMessage::GetOperationCheckpoint {
                        operation_id,
                        response_tx,
                    })
                    .await
                    .map_err(|_| EngineError::WriterClosed)?;
                Ok(OperationRuntimeResponse::Checkpoint(
                    ControlWalHandle::response(response_rx).await?,
                ))
            }
            OperationRuntimeRequest::ListNonterminalCheckpoints => {
                let (response_tx, response_rx) = oneshot::channel();
                wal.tx
                    .send(ControlWalMessage::ListNonterminalOperationCheckpoints { response_tx })
                    .await
                    .map_err(|_| EngineError::WriterClosed)?;
                Ok(OperationRuntimeResponse::Checkpoints(
                    ControlWalHandle::response(response_rx).await?,
                ))
            }
            OperationRuntimeRequest::DeleteTerminalCheckpoint(operation_id) => {
                let (response_tx, response_rx) = oneshot::channel();
                wal.tx
                    .send(ControlWalMessage::DeleteTerminalOperationCheckpoint {
                        operation_id,
                        response_tx,
                    })
                    .await
                    .map_err(|_| EngineError::WriterClosed)?;
                Ok(OperationRuntimeResponse::Bool(
                    ControlWalHandle::response(response_rx).await?,
                ))
            }
            OperationRuntimeRequest::LoadRestartWindow(key) => {
                let (response_tx, response_rx) = oneshot::channel();
                wal.tx
                    .send(ControlWalMessage::LoadRestartWindow { key, response_tx })
                    .await
                    .map_err(|_| EngineError::WriterClosed)?;
                Ok(OperationRuntimeResponse::RestartWindow(
                    ControlWalHandle::response(response_rx).await?,
                ))
            }
            OperationRuntimeRequest::PutRestartWindow(window) => {
                let (response_tx, response_rx) = oneshot::channel();
                wal.tx
                    .send(ControlWalMessage::PutRestartWindow {
                        window,
                        response_tx,
                    })
                    .await
                    .map_err(|_| EngineError::WriterClosed)?;
                ControlWalHandle::response(response_rx).await?;
                Ok(OperationRuntimeResponse::Unit)
            }
            OperationRuntimeRequest::PutSealStaging(checkpoint) => {
                let (response_tx, response_rx) = oneshot::channel();
                wal.tx
                    .send(ControlWalMessage::PutSealStagingCheckpoint {
                        checkpoint,
                        response_tx,
                    })
                    .await
                    .map_err(|_| EngineError::WriterClosed)?;
                ControlWalHandle::response(response_rx).await?;
                Ok(OperationRuntimeResponse::Unit)
            }
            OperationRuntimeRequest::LoadIncompleteSealStaging => {
                let (response_tx, response_rx) = oneshot::channel();
                wal.tx
                    .send(ControlWalMessage::LoadIncompleteSealStaging { response_tx })
                    .await
                    .map_err(|_| EngineError::WriterClosed)?;
                Ok(OperationRuntimeResponse::SealStaging(
                    ControlWalHandle::response(response_rx).await?,
                ))
            }
            OperationRuntimeRequest::RemoveSealStaging(seal_attempt_id) => {
                let (response_tx, response_rx) = oneshot::channel();
                wal.tx
                    .send(ControlWalMessage::RemoveSealStagingCheckpoint {
                        seal_attempt_id,
                        response_tx,
                    })
                    .await
                    .map_err(|_| EngineError::WriterClosed)?;
                Ok(OperationRuntimeResponse::Bool(
                    ControlWalHandle::response(response_rx).await?,
                ))
            }
            OperationRuntimeRequest::GetRecoveryCursor => {
                let (response_tx, response_rx) = oneshot::channel();
                wal.tx
                    .send(ControlWalMessage::GetSupervisionRecoveryCursor { response_tx })
                    .await
                    .map_err(|_| EngineError::WriterClosed)?;
                Ok(OperationRuntimeResponse::Cursor(
                    ControlWalHandle::response(response_rx).await?,
                ))
            }
            OperationRuntimeRequest::PutRecoveryCursor(cursor) => {
                let (response_tx, response_rx) = oneshot::channel();
                wal.tx
                    .send(ControlWalMessage::PutSupervisionRecoveryCursor {
                        cursor,
                        response_tx,
                    })
                    .await
                    .map_err(|_| EngineError::WriterClosed)?;
                ControlWalHandle::response(response_rx).await?;
                Ok(OperationRuntimeResponse::Unit)
            }
        }
    }
}

fn disabled_runtime_response(request: &OperationRuntimeRequest) -> OperationRuntimeResponse {
    match request {
        OperationRuntimeRequest::PutCheckpoint(_)
        | OperationRuntimeRequest::PutRestartWindow(_)
        | OperationRuntimeRequest::PutSealStaging(_)
        | OperationRuntimeRequest::PutRecoveryCursor(_) => OperationRuntimeResponse::Unit,
        OperationRuntimeRequest::GetCheckpoint(_) => OperationRuntimeResponse::Checkpoint(None),
        OperationRuntimeRequest::ListNonterminalCheckpoints => {
            OperationRuntimeResponse::Checkpoints(Vec::new())
        }
        OperationRuntimeRequest::DeleteTerminalCheckpoint(_)
        | OperationRuntimeRequest::RemoveSealStaging(_) => OperationRuntimeResponse::Bool(false),
        OperationRuntimeRequest::LoadRestartWindow(_) => {
            OperationRuntimeResponse::RestartWindow(None)
        }
        OperationRuntimeRequest::LoadIncompleteSealStaging => {
            OperationRuntimeResponse::SealStaging(Vec::new())
        }
        OperationRuntimeRequest::GetRecoveryCursor => OperationRuntimeResponse::Cursor(None),
    }
}

fn unexpected_runtime_response(response: OperationRuntimeResponse) -> EngineError {
    let detail = format!("operation runtime proxy returned an unexpected response: {response:?}");
    drop(response);
    EngineError::RuntimeSupervision(detail)
}

#[derive(Clone)]
pub struct WriterHandle {
    tx: mpsc::Sender<WriterMessage>,
    metrics: Arc<WriterRuntimeMetrics>,
    operation_runtime: OperationRuntimeHandle,
}

pub struct WriterActor {
    wal_actor: ControlWalActor,
    wal_handle: ControlWalHandle,
    wal_shutdown_tx: Option<oneshot::Sender<()>>,
    store: CanonicalStore,
    rx: mpsc::Receiver<WriterMessage>,
    shutdown_rx: Option<oneshot::Receiver<()>>,
    projection_notifier: Option<CognitiveProjectionCoordinatorHandle>,
    config: WriterConfig,
    metrics: Arc<WriterRuntimeMetrics>,
}

pub struct WriterShutdownHandle {
    shutdown_tx: oneshot::Sender<()>,
}

impl WriterShutdownHandle {
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

impl WriterActor {
    pub fn channel(
        wal: ControlWal,
        store: CanonicalStore,
        config: &WriterConfig,
    ) -> (WriterHandle, Self) {
        Self::channel_inner(wal, store, config, None, None)
    }

    pub fn channel_with_projection_notifier(
        wal: ControlWal,
        store: CanonicalStore,
        config: &WriterConfig,
        projection_notifier: CognitiveProjectionCoordinatorHandle,
    ) -> (WriterHandle, Self, WriterShutdownHandle) {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (handle, actor) = Self::channel_inner(
            wal,
            store,
            config,
            Some(projection_notifier),
            Some(shutdown_rx),
        );
        (handle, actor, WriterShutdownHandle { shutdown_tx })
    }

    fn channel_inner(
        wal: ControlWal,
        store: CanonicalStore,
        config: &WriterConfig,
        projection_notifier: Option<CognitiveProjectionCoordinatorHandle>,
        shutdown_rx: Option<oneshot::Receiver<()>>,
    ) -> (WriterHandle, Self) {
        let queue_capacity = config.queue_capacity.max(1);
        let lane_count = config.lane_count.max(1).min(queue_capacity);
        let (tx, rx) = mpsc::channel(queue_capacity);
        let metrics = Arc::new(WriterRuntimeMetrics::new(lane_count));
        let (wal_shutdown_tx, wal_shutdown_rx) = if shutdown_rx.is_some() {
            let (tx, rx) = oneshot::channel();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let (wal_handle, wal_actor) = if let Some(wal_shutdown_rx) = wal_shutdown_rx {
            ControlWalActor::channel_inner(
                wal,
                config.control_wal_queue_capacity,
                config.control_wal_staging_batch_size,
                Some(wal_shutdown_rx),
            )
        } else {
            ControlWalActor::channel(
                wal,
                config.control_wal_queue_capacity,
                config.control_wal_staging_batch_size,
            )
        };
        (
            WriterHandle {
                tx,
                metrics: Arc::clone(&metrics),
                operation_runtime: OperationRuntimeHandle {
                    wal: Some(wal_handle.clone()),
                    proxy: None,
                },
            },
            Self {
                wal_actor,
                wal_handle,
                wal_shutdown_tx,
                store,
                rx,
                shutdown_rx,
                projection_notifier,
                config: WriterConfig {
                    queue_capacity,
                    lane_count,
                    control_wal_queue_capacity: config.control_wal_queue_capacity.max(1),
                    control_wal_staging_batch_size: config.control_wal_staging_batch_size.max(1),
                    unknown_commit_retry_limit: config.unknown_commit_retry_limit.min(1),
                    unknown_commit_retry_delay: config.unknown_commit_retry_delay,
                },
                metrics,
            },
        )
    }

    pub async fn run(self) {
        let Self {
            wal_actor,
            wal_handle,
            wal_shutdown_tx,
            store,
            rx,
            shutdown_rx,
            projection_notifier,
            config,
            metrics,
        } = self;
        let wal_task = tokio::spawn(wal_actor.run());
        let worker = WriterWorker {
            wal: wal_handle,
            store,
            projection_notifier,
            retry_limit: config.unknown_commit_retry_limit,
            retry_delay: config.unknown_commit_retry_delay,
        };
        WriterCoordinator {
            ingress: rx,
            shutdown: shutdown_rx,
            worker,
            config,
            metrics,
        }
        .run()
        .await;
        if let Some(shutdown_tx) = wal_shutdown_tx {
            let _ = shutdown_tx.send(());
        }
        let _ = wal_task.await;
    }
}

struct ProjectJob {
    message: WriterMessage,
    retry_count: u8,
}

#[derive(Default)]
struct ProjectPauseTable {
    unknown_by_project: HashMap<ProjectId, WriteId>,
}

impl ProjectPauseTable {
    fn check_submission(
        &self,
        project_id: ProjectId,
        write_id: WriteId,
    ) -> Result<(), EngineError> {
        if let Some(unknown_write_id) = self.unknown_by_project.get(&project_id).copied()
            && unknown_write_id != write_id
        {
            return Err(EngineError::ProjectWritePaused {
                project_id,
                unknown_write_id,
            });
        }
        Ok(())
    }

    fn pause(&mut self, project_id: ProjectId, write_id: WriteId) {
        self.unknown_by_project.insert(project_id, write_id);
    }

    fn resolve_if_exact(
        &mut self,
        project_id: ProjectId,
        write_id: WriteId,
        succeeded: bool,
    ) -> bool {
        if succeeded && self.unknown_by_project.get(&project_id) == Some(&write_id) {
            self.unknown_by_project.remove(&project_id);
            return true;
        }
        false
    }

    fn len(&self) -> usize {
        self.unknown_by_project.len()
    }
}

enum ProjectJobOutcome {
    Complete {
        write_id: WriteId,
        succeeded: bool,
        project_pause: Option<WriteId>,
    },
    Retry {
        job: Box<ProjectJob>,
        delay: Duration,
    },
}

struct LaneCompletion {
    lane_index: usize,
    project_id: ProjectId,
    outcome: ProjectJobOutcome,
}

/// Bounded project-aware scheduler for canonical writer lanes.
///
/// A project remains active across a delayed retry, but the lane is returned to
/// the idle pool immediately. This is what prevents a retry timer from blocking
/// unrelated projects assigned to the same lane.
pub struct WriterCoordinator {
    ingress: mpsc::Receiver<WriterMessage>,
    shutdown: Option<oneshot::Receiver<()>>,
    worker: WriterWorker,
    config: WriterConfig,
    metrics: Arc<WriterRuntimeMetrics>,
}

impl WriterCoordinator {
    #[allow(clippy::too_many_lines)]
    async fn run(mut self) {
        let lane_count = self.config.lane_count.max(1);
        let (completion_tx, mut completion_rx) = mpsc::channel(lane_count);
        let (delayed_tx, mut delayed_rx) = mpsc::channel(self.config.queue_capacity);
        let mut lane_senders = Vec::with_capacity(lane_count);
        let mut lane_tasks = Vec::with_capacity(lane_count);
        for lane_index in 0..lane_count {
            let (lane_tx, mut lane_rx) = mpsc::channel::<ProjectJob>(1);
            let worker = self.worker.clone();
            let completion_tx = completion_tx.clone();
            lane_senders.push(lane_tx);
            lane_tasks.push(tokio::spawn(async move {
                while let Some(job) = lane_rx.recv().await {
                    let project_id = job.message.project_id();
                    let outcome = worker.process(job).await;
                    if completion_tx
                        .send(LaneCompletion {
                            lane_index,
                            project_id,
                            outcome,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }));
        }
        drop(completion_tx);

        let mut ingress_open = true;
        let mut idle_lanes = (0..lane_count).collect::<VecDeque<_>>();
        let mut project_queues = HashMap::<ProjectId, VecDeque<ProjectJob>>::new();
        let mut ready_projects = VecDeque::<ProjectId>::new();
        let mut retry_ready = VecDeque::<ProjectJob>::new();
        let mut active_projects = HashSet::<ProjectId>::new();
        let mut paused_projects = ProjectPauseTable::default();
        let mut delayed_count = 0usize;
        let mut shutdown = self.shutdown.take();
        let mut shutdown_armed = shutdown.is_some();

        loop {
            while let Some(lane_index) = idle_lanes.pop_front() {
                let job = if let Some(job) = retry_ready.pop_front() {
                    self.metrics.project_started();
                    Some(job)
                } else {
                    let mut selected = None;
                    while let Some(project_id) = ready_projects.pop_front() {
                        let Some(queue) = project_queues.get_mut(&project_id) else {
                            continue;
                        };
                        if let Some(job) = queue.pop_front() {
                            if queue.is_empty() {
                                project_queues.remove(&project_id);
                            }
                            active_projects.insert(project_id);
                            self.metrics.project_started();
                            selected = Some(job);
                            break;
                        }
                    }
                    selected
                };
                let Some(job) = job else {
                    idle_lanes.push_front(lane_index);
                    break;
                };
                if let Err(error) = lane_senders[lane_index].send(job).await {
                    let project_id = error.0.message.project_id();
                    active_projects.remove(&project_id);
                    self.metrics.project_finished();
                    error.0.message.reject(EngineError::WriterClosed);
                    idle_lanes.push_front(lane_index);
                }
            }

            let pending_count = project_queues.values().map(VecDeque::len).sum::<usize>();
            if !ingress_open
                && active_projects.is_empty()
                && pending_count == 0
                && retry_ready.is_empty()
                && delayed_count == 0
            {
                break;
            }

            tokio::select! {
                () = async {
                    if let Some(receiver) = shutdown.as_mut() {
                        let _ = receiver.await;
                    }
                }, if shutdown_armed => {
                    self.ingress.close();
                    shutdown_armed = false;
                }
                message = self.ingress.recv(), if ingress_open => {
                    let Some(message) = message else {
                        ingress_open = false;
                        continue;
                    };
                    let project_id = message.project_id();
                    let write_id = message.write_id();
                    if let Err(error) = paused_projects.check_submission(project_id, write_id) {
                        message.reject(error);
                        continue;
                    }
                    let buffered = active_projects
                        .len()
                        .saturating_add(pending_count)
                        .saturating_add(retry_ready.len())
                        .saturating_add(delayed_count);
                    if buffered >= self.config.queue_capacity {
                        self.metrics
                            .rejected_backpressure
                            .fetch_add(1, Ordering::Relaxed);
                        message.reject(EngineError::Backpressure);
                        continue;
                    }
                    self.metrics.accepted_messages.fetch_add(1, Ordering::Relaxed);
                    let queue = project_queues.entry(project_id).or_default();
                    let was_empty = queue.is_empty();
                    queue.push_back(ProjectJob {
                        message,
                        retry_count: 0,
                    });
                    if was_empty && !active_projects.contains(&project_id) {
                        ready_projects.push_back(project_id);
                    }
                }
                Some(completion) = completion_rx.recv() => {
                    idle_lanes.push_back(completion.lane_index);
                    match completion.outcome {
                        ProjectJobOutcome::Retry { job, delay } => {
                            self.metrics.project_finished();
                            delayed_count = delayed_count.saturating_add(1);
                            self.metrics.scheduled_retries.fetch_add(1, Ordering::Relaxed);
                            let delayed_tx = delayed_tx.clone();
                            tokio::spawn(async move {
                                sleep(delay).await;
                                let _ = delayed_tx.send(*job).await;
                            });
                        }
                        ProjectJobOutcome::Complete {
                            write_id,
                            succeeded,
                            project_pause,
                        } => {
                            active_projects.remove(&completion.project_id);
                            self.metrics.project_finished();
                            if let Some(unknown_write_id) = project_pause {
                                paused_projects.pause(completion.project_id, unknown_write_id);
                                self.metrics
                                    .paused_projects
                                    .store(paused_projects.len(), Ordering::Relaxed);
                                if let Some(mut queue) =
                                    project_queues.remove(&completion.project_id)
                                {
                                    while let Some(job) = queue.pop_front() {
                                        job.message.reject(EngineError::ProjectWritePaused {
                                            project_id: completion.project_id,
                                            unknown_write_id,
                                        });
                                    }
                                }
                            } else {
                                if paused_projects.resolve_if_exact(
                                    completion.project_id,
                                    write_id,
                                    succeeded,
                                ) {
                                    self.metrics
                                        .paused_projects
                                        .store(paused_projects.len(), Ordering::Relaxed);
                                }
                                if project_queues
                                    .get(&completion.project_id)
                                    .is_some_and(|queue| !queue.is_empty())
                                {
                                    ready_projects.push_back(completion.project_id);
                                }
                            }
                        }
                    }
                }
                Some(job) = delayed_rx.recv(), if delayed_count > 0 => {
                    delayed_count = delayed_count.saturating_sub(1);
                    retry_ready.push_back(job);
                }
            }
        }

        drop(lane_senders);
        for task in lane_tasks {
            let _ = task.await;
        }
    }
}

#[derive(Clone)]
struct WriterWorker {
    wal: ControlWalHandle,
    store: CanonicalStore,
    projection_notifier: Option<CognitiveProjectionCoordinatorHandle>,
    retry_limit: u8,
    retry_delay: Duration,
}

enum WriteApplyOutcome {
    Complete(Box<Result<WriteReceipt, EngineError>>),
    Retry {
        envelope: Box<MemoryWriteEnvelope>,
        delay: Duration,
    },
}

impl WriteApplyOutcome {
    fn complete(result: Result<WriteReceipt, EngineError>) -> Self {
        Self::Complete(Box::new(result))
    }
}

fn finish_memory_response(
    write_id: WriteId,
    response_tx: oneshot::Sender<Result<WriteReceipt, EngineError>>,
    result: Result<WriteReceipt, EngineError>,
) -> ProjectJobOutcome {
    let succeeded = result.is_ok();
    let project_pause = match &result {
        Err(
            EngineError::UnknownCommit { write_id }
            | EngineError::RetryableWriteUnavailable { write_id, .. },
        ) => Some(*write_id),
        _ => None,
    };
    let _ = response_tx.send(result);
    ProjectJobOutcome::Complete {
        write_id,
        succeeded,
        project_pause,
    }
}

impl WriterWorker {
    async fn process(&self, job: ProjectJob) -> ProjectJobOutcome {
        let retry_count = job.retry_count;
        match job.message {
            WriterMessage::Write(request) => {
                let write_id = request.envelope.write_id;
                match self.apply(request.envelope, retry_count).await {
                    WriteApplyOutcome::Complete(result) => {
                        finish_memory_response(write_id, request.response_tx, *result)
                    }
                    WriteApplyOutcome::Retry { envelope, delay } => ProjectJobOutcome::Retry {
                        job: Box::new(ProjectJob {
                            message: WriterMessage::Write(WriterRequest {
                                envelope: *envelope,
                                response_tx: request.response_tx,
                            }),
                            retry_count: retry_count.saturating_add(1),
                        }),
                        delay,
                    },
                }
            }
            WriterMessage::Observability {
                envelope,
                response_tx,
            } => {
                let write_id = envelope.write_id;
                let result = self.apply_observability(envelope).await;
                let succeeded = result.is_ok();
                let _ = response_tx.send(result);
                ProjectJobOutcome::Complete {
                    write_id,
                    succeeded,
                    project_pause: None,
                }
            }
            WriterMessage::CognitiveBegin {
                envelope,
                precondition,
                response_tx,
            } => {
                let write_id = envelope.write_id;
                if let Err(error) = self.validate_cognitive_begin(&precondition).await {
                    return finish_memory_response(write_id, response_tx, Err(error));
                }
                match self.apply(*envelope, retry_count).await {
                    WriteApplyOutcome::Complete(result) => {
                        finish_memory_response(write_id, response_tx, *result)
                    }
                    WriteApplyOutcome::Retry { envelope, delay } => ProjectJobOutcome::Retry {
                        job: Box::new(ProjectJob {
                            message: WriterMessage::CognitiveBegin {
                                envelope,
                                precondition,
                                response_tx,
                            },
                            retry_count: retry_count.saturating_add(1),
                        }),
                        delay,
                    },
                }
            }
            WriterMessage::CognitiveTerminal {
                envelope,
                precondition,
                response_tx,
            } => {
                let write_id = envelope.write_id;
                if let Err(error) = self.validate_cognitive_terminal(&precondition).await {
                    return finish_memory_response(write_id, response_tx, Err(error));
                }
                match self.apply(*envelope, retry_count).await {
                    WriteApplyOutcome::Complete(result) => {
                        finish_memory_response(write_id, response_tx, *result)
                    }
                    WriteApplyOutcome::Retry { envelope, delay } => ProjectJobOutcome::Retry {
                        job: Box::new(ProjectJob {
                            message: WriterMessage::CognitiveTerminal {
                                envelope,
                                precondition,
                                response_tx,
                            },
                            retry_count: retry_count.saturating_add(1),
                        }),
                        delay,
                    },
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

    async fn apply(&self, envelope: MemoryWriteEnvelope, retry_count: u8) -> WriteApplyOutcome {
        match self.apply_inner(envelope, retry_count).await {
            Ok(outcome) => outcome,
            Err(error) => WriteApplyOutcome::complete(Err(error)),
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn apply_inner(
        &self,
        mut envelope: MemoryWriteEnvelope,
        retry_count: u8,
    ) -> Result<WriteApplyOutcome, EngineError> {
        let boundary_bytes = serde_json::to_vec(&envelope)?;
        if let Err(violation) = eliot_types::inspect_secret_bytes(&boundary_bytes) {
            return Ok(WriteApplyOutcome::complete(Err(
                EngineError::WriteRejected(format!(
                    "secret boundary rejected memory ingress: {}",
                    violation.rule
                )),
            )));
        }
        if envelope.input_hash.trim().is_empty() {
            return Ok(WriteApplyOutcome::complete(Err(
                EngineError::WriteRejected("input_hash is required".to_owned()),
            )));
        }

        let mut already_staged = false;
        if let Some(existing) = self.wal.get_by_write_id(envelope.write_id).await? {
            match existing {
                WalWriteState::Committed(receipt)
                    if receipt.input_hash == envelope.input_hash
                        && receipt.project_id == envelope.project_id =>
                {
                    let receipt = idempotent_replay(*receipt);
                    self.notify_projection_committed(&envelope, &receipt);
                    return Ok(WriteApplyOutcome::complete(Ok(receipt)));
                }
                WalWriteState::Committed(_) => {
                    return Ok(WriteApplyOutcome::complete(Err(
                        EngineError::WriteRejected("write_id idempotency conflict".to_owned()),
                    )));
                }
                WalWriteState::Pending(pending)
                    if pending.envelope.input_hash == envelope.input_hash
                        && pending.envelope.project_id == envelope.project_id =>
                {
                    let was_unknown = pending.status == WriteStatus::UnknownCommit;
                    envelope = pending.envelope;
                    already_staged = true;
                    if was_unknown {
                        match self.store.write_receipt_by_id(&envelope.write_id).await {
                            Ok(Some(receipt)) if receipt.input_hash == envelope.input_hash => {
                                return Ok(WriteApplyOutcome::complete(
                                    self.handle_store_receipt(
                                        &envelope,
                                        idempotent_replay(receipt),
                                    )
                                    .await,
                                ));
                            }
                            Ok(Some(receipt)) => {
                                let rejected = conflict_receipt(
                                    &envelope,
                                    receipt.memory_revision,
                                    receipt.project_sequence,
                                );
                                self.wal.mark_rejected(rejected).await?;
                                return Ok(WriteApplyOutcome::complete(Err(
                                    EngineError::WriteRejected(
                                        "unknown commit reconciled to input hash conflict"
                                            .to_owned(),
                                    ),
                                )));
                            }
                            Ok(None) if retry_count < self.retry_limit => {
                                return Ok(WriteApplyOutcome::Retry {
                                    envelope: Box::new(envelope),
                                    delay: self.retry_delay,
                                });
                            }
                            Ok(None) => {}
                            Err(error) if is_ambiguous_commit_error(&error) => {
                                return Ok(WriteApplyOutcome::complete(Err(
                                    EngineError::UnknownCommit {
                                        write_id: envelope.write_id,
                                    },
                                )));
                            }
                            Err(error) => {
                                return Ok(WriteApplyOutcome::complete(Err(error.into())));
                            }
                        }
                    }
                }
                WalWriteState::Pending(_) => {
                    return Ok(WriteApplyOutcome::complete(Err(
                        EngineError::WriteRejected(
                            "write_id pending idempotency conflict".to_owned(),
                        ),
                    )));
                }
                WalWriteState::Failed(_) | WalWriteState::DeadLetter(_) => {
                    return Ok(WriteApplyOutcome::complete(Err(
                        EngineError::WriteRejected("write_id already failed".to_owned()),
                    )));
                }
            }
        }

        if envelope.project_sequence_hint.is_none() {
            envelope.project_sequence_hint =
                Some(self.next_project_sequence(envelope.project_id).await?);
        }

        if !already_staged && let Some(raced) = self.wal.stage_pending(envelope.clone()).await? {
            match raced {
                WalWriteState::Committed(receipt)
                    if receipt.input_hash == envelope.input_hash
                        && receipt.project_id == envelope.project_id =>
                {
                    let receipt = idempotent_replay(*receipt);
                    self.notify_projection_committed(&envelope, &receipt);
                    return Ok(WriteApplyOutcome::complete(Ok(receipt)));
                }
                WalWriteState::Pending(pending)
                    if pending.envelope.input_hash == envelope.input_hash
                        && pending.envelope.project_id == envelope.project_id =>
                {
                    return Ok(WriteApplyOutcome::complete(Err(
                        EngineError::WriteRejected(
                            "write_id is already in flight in another writer lane".to_owned(),
                        ),
                    )));
                }
                WalWriteState::Committed(_)
                | WalWriteState::Pending(_)
                | WalWriteState::Failed(_)
                | WalWriteState::DeadLetter(_) => {
                    return Ok(WriteApplyOutcome::complete(Err(
                        EngineError::WriteRejected(
                            "write_id idempotency conflict across writer lanes".to_owned(),
                        ),
                    )));
                }
            }
        }

        self.wal.mark_applying(envelope.write_id).await?;

        match self.store.apply_write_envelope(&envelope).await {
            Ok(receipt) => Ok(WriteApplyOutcome::complete(
                self.handle_store_receipt(&envelope, receipt).await,
            )),
            Err(error) => {
                if is_ambiguous_commit_error(&error) {
                    return self
                        .reconcile_unknown_commit(envelope, error, retry_count)
                        .await;
                }
                if is_retryable_store_unavailable(&error) {
                    let reason = error.to_string();
                    self.wal
                        .mark_retryable(envelope.write_id, reason.clone())
                        .await?;
                    if retry_count < self.retry_limit {
                        return Ok(WriteApplyOutcome::Retry {
                            envelope: Box::new(envelope),
                            delay: self.retry_delay,
                        });
                    }
                    return Ok(WriteApplyOutcome::complete(Err(
                        EngineError::RetryableWriteUnavailable {
                            write_id: envelope.write_id,
                            reason,
                        },
                    )));
                }
                if retry_count == 0 {
                    self.wal
                        .mark_failed(envelope.write_id, error.to_string())
                        .await?;
                } else {
                    self.wal
                        .move_to_dead_letter(envelope.write_id, error.to_string())
                        .await?;
                }
                Ok(WriteApplyOutcome::complete(Err(error.into())))
            }
        }
    }

    async fn apply_observability(
        &self,
        envelope: ObservabilityWriteEnvelope,
    ) -> Result<ObservabilityWriteReceipt, EngineError> {
        let boundary_bytes = serde_json::to_vec(&envelope)?;
        if let Err(violation) = eliot_types::inspect_secret_bytes(&boundary_bytes) {
            return Err(EngineError::WriteRejected(format!(
                "secret boundary rejected observability ingress: {}",
                violation.rule
            )));
        }
        if envelope.input_hash.trim().is_empty() {
            return Err(EngineError::WriteRejected(
                "observability input_hash is required".to_owned(),
            ));
        }
        if envelope.record_id.trim().is_empty() {
            return Err(EngineError::WriteRejected(
                "observability record_id is required".to_owned(),
            ));
        }

        if let Some(mut existing) = self.store.observability_receipt(envelope.write_id).await? {
            if existing.input_hash == envelope.input_hash {
                existing.status = ObservabilityWriteStatus::IdempotentReplay;
                return Ok(existing);
            }
            return Err(EngineError::ObservabilityConflict);
        }

        match self.store.apply_observability(&envelope).await {
            Ok(receipt) => Ok(receipt),
            Err(StoreError::ObservabilityConflict) => Err(EngineError::ObservabilityConflict),
            Err(error) if is_ambiguous_commit_error(&error) => {
                if let Some(existing) = self.store.observability_receipt(envelope.write_id).await? {
                    if existing.input_hash == envelope.input_hash {
                        return Ok(existing);
                    }
                    return Err(EngineError::ObservabilityConflict);
                }
                Err(error.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn handle_store_receipt(
        &self,
        envelope: &MemoryWriteEnvelope,
        receipt: WriteReceipt,
    ) -> Result<WriteReceipt, EngineError> {
        if receipt.status == WriteStatus::Rejected {
            self.wal.mark_rejected(receipt.clone()).await?;
            let reason = receipt.rejected_reason.map_or_else(
                || "write rejected".to_owned(),
                |reason| format!("{reason:?}"),
            );
            return Err(EngineError::WriteRejected(reason));
        }
        self.wal.mark_committed(receipt.clone()).await?;
        self.notify_projection_committed(envelope, &receipt);
        Ok(receipt)
    }

    fn notify_projection_committed(&self, envelope: &MemoryWriteEnvelope, receipt: &WriteReceipt) {
        if let Some(notifier) = &self.projection_notifier {
            notifier.notify_committed(envelope.clone(), receipt.clone());
        }
    }

    async fn reconcile_unknown_commit(
        &self,
        envelope: MemoryWriteEnvelope,
        error: StoreError,
        retry_count: u8,
    ) -> Result<WriteApplyOutcome, EngineError> {
        self.wal
            .mark_unknown_commit(envelope.write_id, error.to_string())
            .await?;
        match self.store.write_receipt_by_id(&envelope.write_id).await {
            Ok(Some(receipt)) if receipt.input_hash == envelope.input_hash => {
                Ok(WriteApplyOutcome::complete(
                    self.handle_store_receipt(&envelope, idempotent_replay(receipt))
                        .await,
                ))
            }
            Ok(Some(receipt)) => {
                let rejected =
                    conflict_receipt(&envelope, receipt.memory_revision, receipt.project_sequence);
                self.wal.mark_rejected(rejected).await?;
                Ok(WriteApplyOutcome::complete(Err(
                    EngineError::WriteRejected(
                        "unknown commit reconciled to input hash conflict".to_owned(),
                    ),
                )))
            }
            Ok(None) if retry_count < self.retry_limit => Ok(WriteApplyOutcome::Retry {
                envelope: Box::new(envelope),
                delay: self.retry_delay,
            }),
            Ok(None)
            | Err(
                StoreError::ConnectionClosed
                | StoreError::Timeout { .. }
                | StoreError::WebSocket(_),
            ) => Ok(WriteApplyOutcome::complete(Err(
                EngineError::UnknownCommit {
                    write_id: envelope.write_id,
                },
            ))),
            Err(error) => Ok(WriteApplyOutcome::complete(Err(error.into()))),
        }
    }

    async fn next_project_sequence(
        &self,
        project_id: eliot_types::ProjectId,
    ) -> Result<ProjectSequence, EngineError> {
        let next = self
            .wal
            .project_heads()
            .await?
            .into_iter()
            .filter(|head| head.project_id == project_id)
            .map(|head| head.project_sequence.value())
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        Ok(ProjectSequence::new(next))
    }
}

fn idempotent_replay(mut receipt: WriteReceipt) -> WriteReceipt {
    receipt.status = WriteStatus::IdempotentReplay;
    receipt
}

fn is_ambiguous_commit_error(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::Timeout { .. } | StoreError::ConnectionClosed | StoreError::WebSocket(_)
    )
}

fn is_retryable_store_unavailable(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::ServerNotFound(_)
            | StoreError::ServerStartFailed(_)
            | StoreError::ServerAuthFailed(_)
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
    pub fn metrics(&self) -> WriterMetricsSnapshot {
        self.metrics.snapshot()
    }

    #[must_use]
    pub fn operation_runtime(&self) -> OperationRuntimeHandle {
        self.operation_runtime.clone()
    }

    fn enqueue(&self, message: WriterMessage) -> Result<(), EngineError> {
        self.tx.try_send(message).map_err(|_| {
            self.metrics
                .rejected_backpressure
                .fetch_add(1, Ordering::Relaxed);
            EngineError::Backpressure
        })
    }

    pub async fn submit(&self, envelope: MemoryWriteEnvelope) -> Result<WriteReceipt, EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        let request = WriterRequest {
            envelope,
            response_tx,
        };
        self.enqueue(WriterMessage::Write(request))?;
        response_rx.await.map_err(|_| EngineError::WriterClosed)?
    }

    pub async fn submit_observability(
        &self,
        envelope: ObservabilityWriteEnvelope,
    ) -> Result<ObservabilityWriteReceipt, EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.enqueue(WriterMessage::Observability {
            envelope,
            response_tx,
        })?;
        response_rx.await.map_err(|_| EngineError::WriterClosed)?
    }

    pub async fn submit_cognitive_begin(
        &self,
        envelope: MemoryWriteEnvelope,
        precondition: CognitiveBeginPrecondition,
    ) -> Result<WriteReceipt, EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.enqueue(WriterMessage::CognitiveBegin {
            envelope: Box::new(envelope),
            precondition,
            response_tx,
        })?;
        response_rx.await.map_err(|_| EngineError::WriterClosed)?
    }

    pub async fn submit_cognitive_terminal(
        &self,
        envelope: MemoryWriteEnvelope,
        precondition: CognitiveTerminalPrecondition,
    ) -> Result<WriteReceipt, EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.enqueue(WriterMessage::CognitiveTerminal {
            envelope: Box::new(envelope),
            precondition,
            response_tx,
        })?;
        response_rx.await.map_err(|_| EngineError::WriterClosed)?
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ControlWalActor, ProjectPauseTable, WriterActor, WriterConfig, WriterMessage,
        WriterRequest, WriterShutdownHandle, default_writer_lane_count,
    };
    use eliot_store::{CanonicalStore, ControlWal};
    use eliot_types::{
        AgentId, ControlWalConfig, GovernorConfig, IdempotencyOptions, LifecycleStatus,
        LifecycleWriteOptions, MemoryWriteEnvelope, OperationId, ProjectId, SemanticCommandKind,
        TaintClass, Visibility, WriteId,
    };
    use time::OffsetDateTime;
    use tokio::sync::oneshot;
    use tokio::time::Duration;

    #[test]
    fn default_lane_count_is_cpu_bounded() {
        let logical = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        assert_eq!(default_writer_lane_count(), logical.clamp(1, 4));
        assert_eq!(WriterConfig::default().lane_count, logical.clamp(1, 4));
    }

    #[test]
    fn unknown_commit_pauses_only_its_project_until_exact_reconciliation() {
        let affected = ProjectId::new_v7();
        let unrelated = ProjectId::new_v7();
        let unknown = WriteId::new_v7();
        let later = WriteId::new_v7();
        let mut pauses = ProjectPauseTable::default();

        pauses.pause(affected, unknown);
        assert!(pauses.check_submission(affected, unknown).is_ok());
        assert!(matches!(
            pauses.check_submission(affected, later),
            Err(crate::EngineError::ProjectWritePaused {
                project_id,
                unknown_write_id,
            }) if project_id == affected && unknown_write_id == unknown
        ));
        assert!(pauses.check_submission(unrelated, later).is_ok());
        assert!(!pauses.resolve_if_exact(affected, later, true));
        assert!(!pauses.resolve_if_exact(affected, unknown, false));
        assert_eq!(pauses.len(), 1);
        assert!(pauses.resolve_if_exact(affected, unknown, true));
        assert_eq!(pauses.len(), 0);
        assert!(pauses.check_submission(affected, later).is_ok());
    }

    #[tokio::test]
    async fn control_wal_actor_stages_one_cross_project_write_id() -> Result<(), crate::EngineError>
    {
        let root = std::env::temp_dir().join(format!("eliot-c5-control-wal-{}", WriteId::new_v7()));
        let path = root.join("control.redb");
        let wal = ControlWal::open(&ControlWalConfig {
            path: path.display().to_string(),
        })?;
        let shared_write_id = WriteId::new_v7();
        let first = envelope(shared_write_id, ProjectId::new_v7(), "first");
        let second = envelope(shared_write_id, ProjectId::new_v7(), "second");
        let (handle, actor) = ControlWalActor::channel(wal, 8, 8);
        let actor_task = tokio::spawn(actor.run());

        let (first_result, second_result) =
            tokio::join!(handle.stage_pending(first), handle.stage_pending(second));
        let outcomes = [first_result?, second_result?];
        assert_eq!(outcomes.iter().filter(|state| state.is_none()).count(), 1);
        assert_eq!(outcomes.iter().filter(|state| state.is_some()).count(), 1);

        drop(handle);
        actor_task.await.map_err(|error| {
            crate::EngineError::WriteRejected(format!("control WAL actor join failed: {error}"))
        })?;
        let wal = ControlWal::open(&ControlWalConfig {
            path: path.display().to_string(),
        })?;
        assert_eq!(wal.pending_count()?, 1);
        drop(wal);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[tokio::test]
    async fn secret_is_rejected_before_control_wal_staging() -> Result<(), crate::EngineError> {
        let root =
            std::env::temp_dir().join(format!("eliot-c5-secret-boundary-{}", WriteId::new_v7()));
        let path = root.join("control.redb");
        let wal = ControlWal::open(&ControlWalConfig {
            path: path.display().to_string(),
        })?;
        let store = CanonicalStore::new(GovernorConfig::default().db.surreal);
        let (handle, actor) = super::WriterActor::channel(wal, store, &WriterConfig::default());
        let actor_task = tokio::spawn(actor.run());
        let mut secret = envelope(WriteId::new_v7(), ProjectId::new_v7(), "secret-input");
        secret.authority = "Authorization: Bearer synthetic-token-value-12345".to_owned();

        let Err(error) = handle.submit(secret).await else {
            return Err(crate::EngineError::WriteRejected(
                "secret-bearing write was unexpectedly accepted".to_owned(),
            ));
        };
        let rendered = error.to_string();
        assert!(rendered.contains("secret boundary rejected memory ingress"));
        assert!(!rendered.contains("synthetic-token-value"));
        drop(handle);
        actor_task.await.map_err(|error| {
            crate::EngineError::WriteRejected(format!("writer actor join failed: {error}"))
        })?;
        let wal = ControlWal::open(&ControlWalConfig {
            path: path.display().to_string(),
        })?;
        assert_eq!(wal.pending_count()?, 0);
        drop(wal);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[tokio::test]
    async fn explicit_shutdown_closes_ingress_and_drains_buffered_writes()
    -> Result<(), crate::EngineError> {
        let root = std::env::temp_dir().join(format!(
            "eliot-c7-writer-drain-shutdown-{}",
            WriteId::new_v7()
        ));
        let path = root.join("control.redb");
        let wal = ControlWal::open(&ControlWalConfig {
            path: path.display().to_string(),
        })?;
        let store = CanonicalStore::new(GovernorConfig::default().db.surreal);
        let config = WriterConfig {
            queue_capacity: 4,
            lane_count: 2,
            ..WriterConfig::default()
        };
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (handle, actor) =
            WriterActor::channel_inner(wal, store, &config, None, Some(shutdown_rx));
        let mut responses = Vec::new();
        for ordinal in 0..3 {
            let (response_tx, response_rx) = oneshot::channel();
            let mut envelope = envelope(
                WriteId::new_v7(),
                ProjectId::new_v7(),
                &format!("shutdown-{ordinal}"),
            );
            envelope.authority =
                format!("Authorization: Bearer synthetic-shutdown-secret-{ordinal}");
            handle.enqueue(WriterMessage::Write(WriterRequest {
                envelope,
                response_tx,
            }))?;
            responses.push(response_rx);
        }

        WriterShutdownHandle { shutdown_tx }.shutdown();
        let actor_task = tokio::spawn(actor.run());
        for response in responses {
            let result = tokio::time::timeout(Duration::from_secs(2), response)
                .await
                .map_err(|_| {
                    crate::EngineError::WriteRejected(
                        "buffered writer response timed out during shutdown".to_owned(),
                    )
                })?
                .map_err(|_| crate::EngineError::WriterClosed)?;
            assert!(matches!(result, Err(crate::EngineError::WriteRejected(_))));
        }
        tokio::time::timeout(Duration::from_secs(2), actor_task)
            .await
            .map_err(|_| {
                crate::EngineError::WriteRejected(
                    "writer actor did not join after explicit shutdown".to_owned(),
                )
            })?
            .map_err(|error| {
                crate::EngineError::WriteRejected(format!("writer actor join failed: {error}"))
            })?;

        drop(handle);
        let wal = ControlWal::open(&ControlWalConfig {
            path: path.display().to_string(),
        })?;
        assert_eq!(wal.pending_count()?, 0);
        drop(wal);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[tokio::test]
    async fn unavailable_store_remains_retryable_and_pauses_only_its_project()
    -> Result<(), crate::EngineError> {
        let root =
            std::env::temp_dir().join(format!("eliot-c5-retryable-outage-{}", WriteId::new_v7()));
        let path = root.join("control.redb");
        let wal = ControlWal::open(&ControlWalConfig {
            path: path.display().to_string(),
        })?;
        let mut surreal = GovernorConfig::default().db.surreal;
        surreal.exe = root.join("missing-surreal.exe").display().to_string();
        let store = CanonicalStore::new(surreal);
        let config = WriterConfig {
            lane_count: 1,
            unknown_commit_retry_delay: tokio::time::Duration::from_millis(1),
            ..WriterConfig::default()
        };
        let (handle, actor) = super::WriterActor::channel(wal, store, &config);
        let actor_task = tokio::spawn(actor.run());
        let project_id = ProjectId::new_v7();
        let retryable_write_id = WriteId::new_v7();

        let Err(error) = handle
            .submit(envelope(retryable_write_id, project_id, "retryable"))
            .await
        else {
            return Err(crate::EngineError::WriteRejected(
                "write unexpectedly committed while SurrealDB was unavailable".to_owned(),
            ));
        };
        assert!(matches!(
            error,
            crate::EngineError::RetryableWriteUnavailable { write_id, .. }
                if write_id == retryable_write_id
        ));
        let metrics = handle.metrics();
        assert_eq!(metrics.scheduled_retries, 1);
        assert_eq!(metrics.paused_projects, 1);

        let later_write_id = WriteId::new_v7();
        let Err(error) = handle
            .submit(envelope(later_write_id, project_id, "must-pause"))
            .await
        else {
            return Err(crate::EngineError::WriteRejected(
                "later project write unexpectedly bypassed retryable outage pause".to_owned(),
            ));
        };
        assert!(matches!(
            error,
            crate::EngineError::ProjectWritePaused {
                project_id: paused_project_id,
                unknown_write_id,
            } if paused_project_id == project_id && unknown_write_id == retryable_write_id
        ));

        drop(handle);
        actor_task.await.map_err(|error| {
            crate::EngineError::WriteRejected(format!("writer actor join failed: {error}"))
        })?;
        let wal = ControlWal::open(&ControlWalConfig {
            path: path.display().to_string(),
        })?;
        assert_eq!(wal.pending_count()?, 1);
        assert_eq!(wal.retryable_count()?, 1);
        assert_eq!(wal.failed_count()?, 0);
        assert_eq!(wal.dead_letter_count()?, 0);
        drop(wal);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    fn envelope(write_id: WriteId, project_id: ProjectId, input_hash: &str) -> MemoryWriteEnvelope {
        MemoryWriteEnvelope {
            write_id,
            operation_id: OperationId::new_v7(),
            agent_id: AgentId::new_v7(),
            session_id: None,
            project_id,
            task_id: None,
            command_kind: SemanticCommandKind::ToolObservationRecord,
            input_hash: input_hash.to_owned(),
            policy_snapshot_id: Some("policy:c5-writer-lanes".to_owned()),
            project_sequence_hint: None,
            created_at: OffsetDateTime::now_utc(),
            scope: "c5-control-wal-actor-test".to_owned(),
            authority: "local-test".to_owned(),
            task_contracts: Vec::new(),
            source_snapshots: Vec::new(),
            evidence_atoms: Vec::new(),
            tool_observations: Vec::new(),
            failures: Vec::new(),
            claims: Vec::new(),
            verification_runs: Vec::new(),
            relations: Vec::new(),
            lifecycle: LifecycleWriteOptions {
                status: LifecycleStatus::Active,
                visibility: Visibility::Internal,
                taint: TaintClass::LocalVerified,
            },
            idempotency: IdempotencyOptions { allow_replay: true },
        }
    }
}
