//! The single bounded execution boundary for governed instruments.
//!
//! This crate owns orchestration, not physical effects.  A composition root
//! supplies an admitted [`InstrumentRequestPort`] and the production
//! [`eliot_process::ProcessExecutor`].  The runner validates every hand-off,
//! preserves request identity and generation, and never converts process
//! failure into semantic verification evidence.

#![forbid(unsafe_code)]

use std::sync::Arc;

use eliot_instrument_api::{ExecutionStatus, InstrumentInvocation};
use eliot_process::{
    CancellationReceipt, OperationId, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError,
    ProcessExecutionView, ProcessExecutor, ProcessRequest, ProcessStartReceipt,
};
use thiserror::Error;

/// Stable identity of the shared instrument runner contract.
pub const CONTRACT_NAME: &str = "eliot.instrument.runner";
/// Wire revision of the runner contract.
pub const CONTRACT_VERSION: (u16, u16, u16) = (1, 0, 0);

/// Supplies the already-authorized, immutable process request for an invocation.
///
/// The implementation belongs to the runtime composition root.  It must obtain
/// executable identity, limits, generation, environment projection, and fence
/// from the owning authority; the runner never derives or replaces them.
pub trait InstrumentRequestPort: Send + Sync {
    /// Binds one admitted invocation to exactly one P-03 process request.
    fn bind(&self, invocation: &InstrumentInvocation) -> Result<ProcessRequest, RunnerError>;
}

/// Failures raised by admission, identity checks, or process execution.
#[derive(Debug, Error)]
pub enum RunnerError {
    /// The provider-neutral invocation failed structural validation.
    #[error("invalid instrument invocation: {0}")]
    InvalidInvocation(String),
    /// The request port rejected the binding.
    #[error("instrument request binding failed: {0}")]
    Binding(String),
    /// The process implementation rejected the operation.
    #[error(transparent)]
    Process(#[from] ProcessExecutionError),
    /// The process request was not correlated to the instrument request.
    #[error("instrument and process operation identities do not match")]
    IdentityMismatch,
    /// A returned receipt did not preserve the immutable process request.
    #[error("process receipt does not preserve the bound request")]
    ReceiptMismatch,
    /// A result was requested for a different operation than the binding.
    #[error("process observation does not preserve the bound request")]
    ObservationMismatch,
}

/// The immutable invocation/request pair used for every runner operation.
#[derive(Debug)]
pub struct InstrumentBinding {
    /// Provider-neutral instrument invocation.
    pub invocation: InstrumentInvocation,
    /// Exact sealed process request delegated to P-03.
    process_request: Option<ProcessRequest>,
    operation_id: OperationId,
    request_digest: String,
    generation: u64,
}

impl InstrumentBinding {
    /// Validates and binds an invocation through the owning request port.
    pub fn bind(
        invocation: InstrumentInvocation,
        port: &dyn InstrumentRequestPort,
    ) -> Result<Self, RunnerError> {
        invocation
            .validate()
            .map_err(|error| RunnerError::InvalidInvocation(error.to_string()))?;
        let process_request = port.bind(&invocation)?;
        process_request
            .validate()
            .map_err(|error| RunnerError::Binding(error.to_string()))?;
        if process_request.operation_id().as_str() != invocation.request.request_id.as_str() {
            return Err(RunnerError::IdentityMismatch);
        }
        Ok(Self {
            invocation,
            operation_id: process_request.operation_id().clone(),
            request_digest: process_request.invocation_digest().to_owned(),
            generation: process_request.generation().get(),
            process_request: Some(process_request),
        })
    }

    /// Creates a binding from a request already checked by the composition root.
    pub fn from_request(
        invocation: InstrumentInvocation,
        process_request: ProcessRequest,
    ) -> Result<Self, RunnerError> {
        invocation
            .validate()
            .map_err(|error| RunnerError::InvalidInvocation(error.to_string()))?;
        process_request
            .validate()
            .map_err(|error| RunnerError::Binding(error.to_string()))?;
        if process_request.operation_id().as_str() != invocation.request.request_id.as_str() {
            return Err(RunnerError::IdentityMismatch);
        }
        Ok(Self {
            invocation,
            operation_id: process_request.operation_id().clone(),
            request_digest: process_request.invocation_digest().to_owned(),
            generation: process_request.generation().get(),
            process_request: Some(process_request),
        })
    }

    /// Returns the operation identity without exposing the consuming request.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }
}

/// Receipt returned after the physical executor accepts an instrument.
#[derive(Debug)]
pub struct InstrumentStartReceipt {
    /// Original provider-neutral invocation.
    pub invocation: InstrumentInvocation,
    /// P-03 acceptance receipt.
    pub process: ProcessStartReceipt,
}

/// Current process observation correlated to its instrument invocation.
#[derive(Clone, Debug)]
pub struct InstrumentObservation {
    /// Original provider-neutral invocation.
    pub invocation: InstrumentInvocation,
    /// Current process view.
    pub view: ProcessExecutionView,
    /// Execution axis only; no semantic verifier result is inferred.
    pub execution: ExecutionStatus,
}

/// The bounded facade over the injected physical process executor.
pub struct InstrumentRunner<E> {
    executor: Arc<E>,
}

impl<E> InstrumentRunner<E> {
    /// Creates a runner around the active production process executor.
    #[must_use]
    pub fn new(executor: Arc<E>) -> Self {
        Self { executor }
    }
}

impl<E: ProcessExecutor + 'static> InstrumentRunner<E> {
    /// Binds an invocation and launches it through P-03.
    pub async fn launch_bound(
        &self,
        invocation: InstrumentInvocation,
        port: &dyn InstrumentRequestPort,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<InstrumentStartReceipt, RunnerError> {
        let mut binding = InstrumentBinding::bind(invocation, port)?;
        self.launch(&mut binding, sink).await
    }

    /// Launches the exact immutable binding through P-03.
    pub async fn launch(
        &self,
        binding: &mut InstrumentBinding,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<InstrumentStartReceipt, RunnerError> {
        let process_request = binding
            .process_request
            .take()
            .ok_or(RunnerError::ReceiptMismatch)?;
        let process = self.executor.start(process_request, sink).await?;
        if process.operation_id() != &binding.operation_id
            || process.request_digest() != binding.request_digest
            || process.accepted_generation().get() != binding.generation
        {
            return Err(RunnerError::ReceiptMismatch);
        }
        Ok(InstrumentStartReceipt {
            invocation: binding.invocation.clone(),
            process,
        })
    }

    /// Inspects an operation and preserves the binding identity.
    pub async fn inspect(
        &self,
        binding: &InstrumentBinding,
    ) -> Result<InstrumentObservation, RunnerError> {
        let view = self.executor.inspect(binding.operation_id.clone()).await?;
        if view.operation_id() != &binding.operation_id
            || view.request_digest() != binding.request_digest
            || view.fence().generation().get() != binding.generation
        {
            return Err(RunnerError::ObservationMismatch);
        }
        Ok(InstrumentObservation {
            invocation: binding.invocation.clone(),
            execution: execution_status(&view),
            view,
        })
    }

    /// Cancels an operation through the process contract's current fence.
    pub async fn cancel(
        &self,
        binding: &InstrumentBinding,
    ) -> Result<CancellationReceipt, RunnerError> {
        Ok(self.executor.cancel(binding.operation_id.clone()).await?)
    }

    /// Reconciles an unknown operation and returns retained process evidence.
    pub async fn reconcile(
        &self,
        binding: &InstrumentBinding,
    ) -> Result<ProcessEvidence, RunnerError> {
        let evidence = self
            .executor
            .reconcile(binding.operation_id.clone())
            .await?;
        if evidence.operation_id() != &binding.operation_id
            || evidence.request_digest() != binding.request_digest
        {
            return Err(RunnerError::ObservationMismatch);
        }
        Ok(evidence)
    }
}

/// Compatibility name for composition roots using the bounded terminology.
pub type BoundedInstrumentRunner<E> = InstrumentRunner<E>;
/// Compatibility name for callers that refer to the runner as an adapter.
pub type InstrumentAdapter<E> = InstrumentRunner<E>;

fn execution_status(view: &ProcessExecutionView) -> ExecutionStatus {
    use eliot_process::{ExitDisposition, ProcessLifecycle};
    match view.lifecycle() {
        ProcessLifecycle::Created | ProcessLifecycle::Starting => ExecutionStatus::Accepted,
        ProcessLifecycle::Running | ProcessLifecycle::Cancelling => ExecutionStatus::Running,
        ProcessLifecycle::UnknownOutcome | ProcessLifecycle::Quarantined => {
            ExecutionStatus::Unknown
        }
        ProcessLifecycle::Reconciled => ExecutionStatus::Partial,
        ProcessLifecycle::Exited | ProcessLifecycle::Failed => {
            match view.exit().map(|exit| exit.disposition()) {
                Some(ExitDisposition::Completed) => ExecutionStatus::Succeeded,
                Some(ExitDisposition::Cancelled) => ExecutionStatus::Cancelled,
                Some(ExitDisposition::Unknown) | None => ExecutionStatus::Unknown,
                _ => ExecutionStatus::Failed,
            }
        }
    }
}
