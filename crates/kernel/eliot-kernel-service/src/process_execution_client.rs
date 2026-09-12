//! Kernel front-door process-execution client over dyn-compatible ports.
//!
//! This module ships only boxed-future ports plus the client that composes
//! them into the [`ProcessExecutionClient`](crate::ProcessExecutionClient)
//! front door. Every awaited future is already a `Send`-proven box, so the
//! client compiles under the `Send` bound without a blanket implementation.
//!
//! The concrete port implementations live in the composition root
//! (`bins/eliot-kernel`), which depends on this crate plus
//! `eliot-process-executor` and `eliot-process`; monomorphization there
//! proves `Send`. This crate must not depend on `eliot-process-executor`
//! (one-way layering), so no concrete implementation may be added here.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use eliot_process::{
    CancellationReceipt, OperationId, ProcessEvidence, ProcessExecutionAdmissionRequest,
    ProcessExecutionError, ProcessExecutionView, ProcessStartReceipt,
};

use crate::{
    ProcessExecutionClient, ProcessExecutionFuture, ProcessExecutionRejection,
    ProcessExecutionRequest, ProcessExecutionResponse,
};

/// Boxed `Send` future for one closed admission through the caller's authority.
pub type ProcessStarterFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ProcessStartReceipt, ProcessExecutionError>> + Send + 'a>>;

/// Starts one closed admission through the caller's authority owner.
///
/// Implementations route to the one active authority; they never mint it.
pub trait ProcessStarter: Send + Sync {
    /// Admits and starts one exact process intent.
    fn start(&self, admission: ProcessExecutionAdmissionRequest) -> ProcessStarterFuture<'_>;
}

/// Boxed `Send` future for one observation/cancel/reconcile operation.
pub type ProcessOperationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ProcessExecutionError>> + Send + 'a>>;

/// Observes, cancels, and reconciles already-admitted operations.
///
/// `Start` is deliberately absent: starting needs authority, which only
/// [`ProcessStarter`] carries. Production implements this trait for the
/// concrete P-04 executor in the composition root, where `Send` is proven at
/// monomorphization; no blanket implementation is provided here because a
/// generic native-`async`-fn bound cannot prove `Send` through the boxed
/// future.
pub trait ProcessOperationPort: Send + Sync {
    /// Inspects one admitted operation.
    fn inspect(
        &self,
        operation_id: OperationId,
    ) -> ProcessOperationFuture<'_, ProcessExecutionView>;

    /// Requests cancellation of one admitted operation.
    fn cancel(&self, operation_id: OperationId) -> ProcessOperationFuture<'_, CancellationReceipt>;

    /// Reconciles one operation after an unknown delivery/result boundary.
    fn reconcile(&self, operation_id: OperationId) -> ProcessOperationFuture<'_, ProcessEvidence>;
}

/// Mechanics-only front-door client composing a starter with an operation port.
pub struct KernelProcessExecutionClient {
    starter: Arc<dyn ProcessStarter>,
    operations: Arc<dyn ProcessOperationPort>,
}

impl KernelProcessExecutionClient {
    /// Composes one authority-carrying starter with one operation port.
    pub fn new(
        starter: Arc<dyn ProcessStarter>,
        operations: Arc<dyn ProcessOperationPort>,
    ) -> Self {
        Self {
            starter,
            operations,
        }
    }
}

impl ProcessExecutionClient for KernelProcessExecutionClient {
    fn execute(&self, request: ProcessExecutionRequest) -> ProcessExecutionFuture<'_> {
        let starter = Arc::clone(&self.starter);
        let operations = Arc::clone(&self.operations);
        Box::pin(async move {
            if let Err(error) = request.validate() {
                return ProcessExecutionResponse::Rejected(ProcessExecutionRejection {
                    code: "CONTRACT_REJECTED".to_owned(),
                    detail: error.to_string().chars().take(512).collect(),
                });
            }
            match request {
                ProcessExecutionRequest::Start(admission) => match starter.start(admission).await {
                    Ok(receipt) => ProcessExecutionResponse::Started(receipt),
                    Err(error) => ProcessExecutionResponse::Rejected(
                        ProcessExecutionRejection::from_error(&error),
                    ),
                },
                ProcessExecutionRequest::Inspect { operation_id } => {
                    match operations.inspect(operation_id).await {
                        Ok(view) => ProcessExecutionResponse::Status(view),
                        Err(error) => ProcessExecutionResponse::Rejected(
                            ProcessExecutionRejection::from_error(&error),
                        ),
                    }
                }
                ProcessExecutionRequest::Cancel { operation_id } => {
                    match operations.cancel(operation_id).await {
                        Ok(receipt) => ProcessExecutionResponse::Cancelled(receipt),
                        Err(error) => ProcessExecutionResponse::Rejected(
                            ProcessExecutionRejection::from_error(&error),
                        ),
                    }
                }
                ProcessExecutionRequest::Reconcile { operation_id } => {
                    match operations.reconcile(operation_id).await {
                        Ok(evidence) => ProcessExecutionResponse::Reconciled(evidence),
                        Err(error) => ProcessExecutionResponse::Rejected(
                            ProcessExecutionRejection::from_error(&error),
                        ),
                    }
                }
            }
        })
    }
}
