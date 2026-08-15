//! Production Cargo instrumentation boundary.
//!
//! This adapter owns Cargo's provider-facing policy and result projection. It
//! does not spawn a process, read the filesystem, mint a fence, or interpret
//! output as proof. Those effects are supplied by the two explicit ports below.

#![forbid(unsafe_code)]

use std::sync::Arc;

use eliot_instrument_api::{ExecutionStatus, InstrumentInvocation};
use eliot_process::{
    CancellationReceipt, OperationId, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError,
    ProcessExecutionView, ProcessExecutor, ProcessRequest, ProcessStartReceipt,
};
use thiserror::Error;

/// Stable identity of the Cargo adapter.
pub const CONTRACT_NAME: &str = "eliot.instrument.cargo";
/// Wire revision of this adapter's receipts.
pub const CONTRACT_VERSION: (u16, u16, u16) = (1, 0, 0);

/// Supplies an already-authorized, sealed process request for Cargo.
///
/// Implementations belong to the runtime composition root. In particular, an
/// implementation must obtain the executable digest, generation, resource
/// limits, and fencing token from the owning control plane rather than deriving
/// or replacing them here.
pub trait CargoProcessRequestPort: Send + Sync {
    /// Binds an admitted instrument invocation to one immutable P-03 request.
    fn bind(&self, invocation: &InstrumentInvocation) -> Result<ProcessRequest, CargoAdapterError>;
}

/// Failures raised before or during a Cargo invocation.
#[derive(Debug, Error)]
pub enum CargoAdapterError {
    /// The provider-neutral invocation was not structurally valid.
    #[error("invalid instrument invocation: {0}")]
    InvalidInvocation(String),
    /// The request port rejected the binding.
    #[error("Cargo process binding failed: {0}")]
    Binding(String),
    /// The process implementation rejected the operation.
    #[error(transparent)]
    Process(#[from] ProcessExecutionError),
    /// The bound process request did not preserve invocation identity.
    #[error("Cargo process binding does not preserve invocation identity")]
    IdentityMismatch,
    /// The physical executor returned a receipt for a different generation.
    #[error("Cargo process receipt does not preserve the bound generation")]
    GenerationMismatch,
}

/// The immutable pair passed between the adapter's admission and execution
/// methods.
#[derive(Debug)]
pub struct CargoBinding {
    /// The provider-neutral invocation admitted by the caller.
    pub invocation: InstrumentInvocation,
    /// The exact request delegated to P-03.
    process_request: Option<ProcessRequest>,
    operation_id: OperationId,
    request_digest: String,
    generation: u64,
}

impl CargoBinding {
    /// Validates the invocation and binds it through an explicit request port.
    pub fn bind(
        invocation: InstrumentInvocation,
        port: &dyn CargoProcessRequestPort,
    ) -> Result<Self, CargoAdapterError> {
        invocation
            .validate()
            .map_err(|error| CargoAdapterError::InvalidInvocation(error.to_string()))?;
        let process_request = port.bind(&invocation)?;
        process_request
            .validate()
            .map_err(|error| CargoAdapterError::Binding(error.to_string()))?;
        if process_request.operation_id().as_str() != invocation.request.request_id.as_str() {
            return Err(CargoAdapterError::IdentityMismatch);
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

/// Receipt returned after P-03 accepts a Cargo process.
#[derive(Debug)]
pub struct CargoStartReceipt {
    /// Original instrument invocation.
    pub invocation: InstrumentInvocation,
    /// P-03's acceptance receipt.
    pub process: ProcessStartReceipt,
}

/// Terminal or currently observable Cargo result.
#[derive(Clone, Debug)]
pub struct CargoObservation {
    /// Original instrument invocation.
    pub invocation: InstrumentInvocation,
    /// Current process view.
    pub view: ProcessExecutionView,
    /// Execution axis only; no verifier meaning is inferred here.
    pub execution: ExecutionStatus,
}

/// The sole adapter facade. Physical effects are exclusively delegated to the
/// injected provider-neutral process executor.
pub struct CargoInstrumentationAdapter<E> {
    executor: Arc<E>,
}

impl<E> CargoInstrumentationAdapter<E> {
    /// Creates an adapter around the active production process executor.
    #[must_use]
    pub fn new(executor: Arc<E>) -> Self {
        Self { executor }
    }
}

impl<E: ProcessExecutor + 'static> CargoInstrumentationAdapter<E> {
    /// Launches the exact bound Cargo request through P-03.
    pub async fn launch(
        &self,
        binding: &mut CargoBinding,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<CargoStartReceipt, CargoAdapterError> {
        let process_request = binding
            .process_request
            .take()
            .ok_or(CargoAdapterError::IdentityMismatch)?;
        let process = self.executor.start(process_request, sink).await?;
        if process.operation_id() != &binding.operation_id {
            return Err(CargoAdapterError::IdentityMismatch);
        }
        if process.accepted_generation().get() != binding.generation {
            return Err(CargoAdapterError::GenerationMismatch);
        }
        Ok(CargoStartReceipt {
            invocation: binding.invocation.clone(),
            process,
        })
    }

    /// Inspects a running or terminal Cargo operation without changing it.
    pub async fn inspect(
        &self,
        binding: &CargoBinding,
    ) -> Result<CargoObservation, CargoAdapterError> {
        let view = self.executor.inspect(binding.operation_id.clone()).await?;
        if view.operation_id() != &binding.operation_id
            || view.request_digest() != binding.request_digest
        {
            return Err(CargoAdapterError::IdentityMismatch);
        }
        Ok(CargoObservation {
            invocation: binding.invocation.clone(),
            execution: execution_status(&view),
            view,
        })
    }

    /// Cancels Cargo through the process contract's current fence.
    pub async fn cancel(
        &self,
        binding: &CargoBinding,
    ) -> Result<CancellationReceipt, CargoAdapterError> {
        Ok(self.executor.cancel(binding.operation_id.clone()).await?)
    }

    /// Reconciles an unknown Cargo result and retains the P-03 evidence record.
    pub async fn reconcile(
        &self,
        binding: &CargoBinding,
    ) -> Result<ProcessEvidence, CargoAdapterError> {
        Ok(self
            .executor
            .reconcile(binding.operation_id.clone())
            .await?)
    }
}

/// Compatibility spelling for composition roots that call the adapter simply
/// `CargoAdapter`.
pub type CargoAdapter<E> = CargoInstrumentationAdapter<E>;

fn execution_status(view: &ProcessExecutionView) -> ExecutionStatus {
    use eliot_process::{ExitDisposition, ProcessLifecycle};
    match view.lifecycle() {
        ProcessLifecycle::Created | ProcessLifecycle::Starting => ExecutionStatus::Accepted,
        ProcessLifecycle::Running | ProcessLifecycle::Cancelling => ExecutionStatus::Running,
        ProcessLifecycle::UnknownOutcome => ExecutionStatus::Unknown,
        ProcessLifecycle::Quarantined => ExecutionStatus::Unknown,
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
