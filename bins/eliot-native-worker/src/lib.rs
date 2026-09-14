//! Thin composition boundary for one isolated native-worker generation.
//!
//! The binary owns framing and process lifetime only. Admission, process
//! execution, evidence, replay, and checkpoint persistence remain injected
//! ports owned by the governing services.

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};

use eliot_native_worker_core::{
    CapabilityAdmissionPort, ClaimAdmissionRequest, DurableCheckpointPort, DurableReplayPort,
    NativeWorkerRegistration, ReadinessSubmission, WorkerCore, WorkerError, WorkerEventEnvelope,
    WorkerFrame, WorkerHello, WorkerLifecycle, WorkerReady,
};
use eliot_process::{ProcessExecutor, ProcessRequest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod kernel_admission_client;

pub use kernel_admission_client::{
    KernelNativeWorkerClient, KernelReplayPort, KernelReplayTransport,
    NATIVE_WORKER_CANCEL_OBSERVE_OPERATION, NATIVE_WORKER_CHECKPOINT_OPERATION,
    NATIVE_WORKER_CLAIM_OPERATION, NATIVE_WORKER_HEARTBEAT_OPERATION,
    NATIVE_WORKER_READY_OPERATION, NATIVE_WORKER_RECONCILE_OPERATION,
    NATIVE_WORKER_REGISTRATION_OPERATION, NATIVE_WORKER_REPLAY_ACKNOWLEDGE_OPERATION,
    NATIVE_WORKER_REPLAY_APPEND_OPERATION, NATIVE_WORKER_REPLAY_BEGIN_OPERATION,
    NATIVE_WORKER_REPLAY_LOOKUP_OPERATION, NATIVE_WORKER_REPLAY_OPERATION,
    NATIVE_WORKER_RESULT_SUBMIT_OPERATION, ReconcileRetainedReceipt, ReconcileSubmission,
};

const MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;
pub const KERNEL_ADMISSION_REQUIRED: &str = "KERNEL_ADMISSION_REQUIRED";

/// A transport response containing only durable events produced by the core.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerResponse {
    /// Events that the replay owner accepted and returned for delivery.
    pub events: Vec<WorkerEventEnvelope>,
}

/// Errors at the process composition boundary.
#[derive(Debug, Error)]
pub enum NativeWorkerError {
    #[error("{KERNEL_ADMISSION_REQUIRED}: {0}")]
    KernelAdmissionRequired(String),
    #[error("worker core error: {0}")]
    Core(#[from] WorkerError),
    #[error("worker transport I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("worker transport JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("native-worker frame is {actual} bytes; maximum is {maximum}")]
    FrameTooLarge { actual: u32, maximum: u32 },
    #[error("native-worker frame length cannot be zero")]
    EmptyFrame,
}

/// Composed native-worker generation with all governing dependencies explicit.
pub struct NativeWorker<E, A, R, C> {
    core: WorkerCore<E, A, R, C>,
}

impl<E, A, R, C> NativeWorker<E, A, R, C>
where
    E: ProcessExecutor,
    A: eliot_native_worker_core::CapabilityAdmissionPort,
    R: eliot_native_worker_core::DurableReplayPort,
    C: eliot_native_worker_core::DurableCheckpointPort,
{
    /// Composes the worker without creating providers or authority locally.
    #[must_use]
    pub fn new(core: WorkerCore<E, A, R, C>) -> Self {
        Self { core }
    }

    /// Performs the governed admission and process start handshake.
    pub async fn start(
        &mut self,
        hello: WorkerHello,
        process: ProcessRequest,
    ) -> Result<eliot_native_worker_core::WorkerReady, NativeWorkerError> {
        self.core
            .demand_start(hello, process)
            .await
            .map_err(NativeWorkerError::from)
    }

    /// Performs the claimed admission and process start handshake for one
    /// exact Kernel-issued claim presentation (T2-S05 first consumer).
    ///
    /// Binds the existing claimed start path without minting authority: the
    /// supplied `claim`, `hello`, and `process` are validated through the
    /// production `from_claim` join and executable gate before the injected
    /// admission port and P-03 executor run. The existing unclaimed `start`
    /// is untouched; `ProcessRequest` stays an in-memory composition value
    /// and never enters a wire type.
    pub async fn start_claimed(
        &mut self,
        claim: eliot_native_worker_core::ClaimAdmissionRequest,
        hello: WorkerHello,
        process: ProcessRequest,
    ) -> Result<eliot_native_worker_core::WorkerReady, NativeWorkerError> {
        self.core
            .demand_start_claimed(claim, hello, process)
            .await
            .map_err(NativeWorkerError::from)
    }

    /// Restores an exact fenced binding and replays durable events.
    pub async fn recover(
        &mut self,
        hello: WorkerHello,
        process: ProcessRequest,
        replay_after_sequence: u64,
    ) -> Result<eliot_native_worker_core::WorkerRecovery, NativeWorkerError> {
        self.core
            .recover_after_restart(hello, process, replay_after_sequence)
            .await
            .map_err(NativeWorkerError::from)
    }

    /// Restores one exact claimed binding after a restart without launching
    /// a second process.
    ///
    /// Preserves the existing unclaimed [`NativeWorker::recover`]; the
    /// production claimed path uses this method so a lost start response or
    /// restart reconciles through retained P-03 inspect plus the durable
    /// replay suffix, never a duplicate start. Invalid admission invokes no
    /// factory and starts nothing; the typed core refusal surfaces instead.
    pub async fn recover_claimed(
        &mut self,
        claim: eliot_native_worker_core::ClaimAdmissionRequest,
        hello: WorkerHello,
        process: ProcessRequest,
        replay_after_sequence: u64,
    ) -> Result<eliot_native_worker_core::WorkerRecovery, NativeWorkerError> {
        self.core
            .recover_after_restart_claimed(claim, hello, process, replay_after_sequence)
            .await
            .map_err(NativeWorkerError::from)
    }

    /// Handles one already-decoded EBP worker frame.
    pub async fn handle(
        &mut self,
        frame: WorkerFrame,
    ) -> Result<Vec<WorkerEventEnvelope>, NativeWorkerError> {
        self.core
            .handle(frame)
            .await
            .map_err(NativeWorkerError::from)
    }

    /// Returns the logical lifecycle owned by the worker protocol.
    #[must_use]
    pub const fn lifecycle(&self) -> WorkerLifecycle {
        self.core.lifecycle()
    }

    /// Serves length-delimited JSON frames after the caller has completed start.
    ///
    /// The blocking stdin read runs on a dedicated reader thread that drains
    /// the OS pipe promptly into a bounded channel, while this loop handles
    /// frames (including `Cancel`/`Heartbeat` bodies through the core) and
    /// writes responses. A slow `Execute` handler therefore cannot starve a
    /// concurrent cancellation or heartbeat observation: the reader keeps
    /// buffering while the handler runs, and cancel/heartbeat frames are
    /// handled as soon as the current frame completes instead of being stuck
    /// behind a blocked read. T9-05 coordinator verification is not consumed
    /// by this contour.
    pub async fn serve_stdio(&mut self) -> Result<(), NativeWorkerError> {
        let (sender, receiver) =
            std::sync::mpsc::sync_channel::<Result<Option<WorkerFrame>, NativeWorkerError>>(64);
        std::thread::spawn(move || {
            loop {
                let frame = read_frame();
                let done = matches!(&frame, Ok(None) | Err(_));
                if sender.send(frame).is_err() || done {
                    return;
                }
            }
        });
        loop {
            let frame = receiver.recv().map_err(|_| {
                NativeWorkerError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "native-worker stdin reader stopped",
                ))
            })??;
            let Some(frame) = frame else {
                return Ok(());
            };
            if self.serve_frame(frame).await? {
                return Ok(());
            }
        }
    }

    /// Handles one frame and writes its response, returning true on shutdown.
    async fn serve_frame(&mut self, frame: WorkerFrame) -> Result<bool, NativeWorkerError> {
        let shutdown = matches!(
            frame.body,
            eliot_native_worker_core::WorkerFrameBody::Shutdown
        );
        let events = self.handle(frame).await?;
        write_frame(&WorkerResponse { events })?;
        Ok(shutdown)
    }

    /// Serves exactly one length-delimited frame from `reader` into `writer`.
    ///
    /// Testable bounded-frame helper for the admitted contour: reads one
    /// frame, handles it through the claimed core, and writes one response.
    /// Returns `Ok(true)` on `Shutdown`, `Ok(false)` otherwise. Uses blocking
    /// I/O like the stdio loop; cancellation/heartbeat split is owned by
    /// [`NativeWorker::serve_stdio`].
    pub async fn serve_one_frame<Reader: Read, Writer: Write>(
        &mut self,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> Result<bool, NativeWorkerError> {
        let Some(frame) = read_frame_from(reader)? else {
            return Ok(true);
        };
        let shutdown = matches!(
            frame.body,
            eliot_native_worker_core::WorkerFrameBody::Shutdown
        );
        let events = self.handle(frame).await?;
        write_frame_to(&WorkerResponse { events }, writer)?;
        Ok(shutdown)
    }
}

/// Thin lifecycle transport for the admitted driver.
///
/// Implemented by [`KernelNativeWorkerClient`] in production and by
/// clearly-marked test doubles where a live Kernel is unavailable. T9-05
/// coordinator verification is not consumed by this contour.
pub trait AdmittedLifecycle {
    /// Registers (or renews) one worker generation.
    fn submit_registration(
        &mut self,
        registration: &NativeWorkerRegistration,
    ) -> Result<serde_json::Value, NativeWorkerError>;
    /// Claims exactly one Kernel-owned execution unit.
    fn submit_claim(
        &mut self,
        admission: &ClaimAdmissionRequest,
    ) -> Result<serde_json::Value, NativeWorkerError>;
    /// Reconciles one exact claim after a lost acknowledgement.
    fn submit_reconcile(
        &mut self,
        submission: &crate::ReconcileSubmission,
    ) -> Result<serde_json::Value, NativeWorkerError>;
    /// Submits one typed ready-or-blocked verdict for the claimed unit.
    fn submit_readiness(
        &mut self,
        submission: &ReadinessSubmission,
    ) -> Result<serde_json::Value, NativeWorkerError>;
}

impl AdmittedLifecycle for KernelNativeWorkerClient {
    fn submit_registration(
        &mut self,
        registration: &NativeWorkerRegistration,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        KernelNativeWorkerClient::submit_registration(self, registration)
    }

    fn submit_claim(
        &mut self,
        admission: &ClaimAdmissionRequest,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        KernelNativeWorkerClient::submit_claim(self, admission)
    }

    fn submit_reconcile(
        &mut self,
        submission: &crate::ReconcileSubmission,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        KernelNativeWorkerClient::submit_reconcile(self, submission)
    }

    fn submit_readiness(
        &mut self,
        submission: &ReadinessSubmission,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        KernelNativeWorkerClient::submit_readiness(self, submission)
    }
}

/// Drives one admitted native-worker generation to `Ready`.
///
/// Sequence: register, claim the exact authenticated unit, reconcile any
/// retained operation (lost start response or restart reconciles through the
/// retained record, never a second process), compose-checked
/// `start_claimed` through the exact `WorkerCore::demand_start_claimed` gate,
/// then submit readiness. Invalid admission fails before any factory or
/// process start is invoked: the lifecycle transport refuses first, and the
/// claimed core gate refuses before P-03 starts anything. No coordinator
/// verification is consumed here (T9-05 is not part of this contour); no user
/// authentication is performed (owner decision #1376); no worker-local replay
/// journal is created (thin transport over T9-03 only).
pub async fn drive_admitted_claimed<E, A, R, C, L>(
    lifecycle: &mut L,
    worker: &mut NativeWorker<E, A, R, C>,
    registration: &NativeWorkerRegistration,
    admission: &ClaimAdmissionRequest,
    hello: WorkerHello,
    process: ProcessRequest,
    reconcile: &crate::ReconcileSubmission,
    readiness: &ReadinessSubmission,
) -> Result<WorkerReady, NativeWorkerError>
where
    E: ProcessExecutor,
    A: CapabilityAdmissionPort,
    R: DurableReplayPort,
    C: DurableCheckpointPort,
    L: AdmittedLifecycle,
{
    lifecycle.submit_registration(registration)?;
    lifecycle.submit_claim(admission)?;
    lifecycle.submit_reconcile(reconcile)?;
    let ready = worker
        .start_claimed(admission.clone(), hello, process)
        .await?;
    lifecycle.submit_readiness(readiness)?;
    Ok(ready)
}

fn write_frame(response: &WorkerResponse) -> Result<(), NativeWorkerError> {
    let mut output = io::stdout().lock();
    write_frame_to(response, &mut output)
}

fn read_frame() -> Result<Option<WorkerFrame>, NativeWorkerError> {
    let mut prefix = [0_u8; 4];
    let mut input = io::stdin().lock();
    match input.read_exact(&mut prefix) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(NativeWorkerError::Io(error)),
    }
    let length = u32::from_le_bytes(prefix);
    if length == 0 {
        return Err(NativeWorkerError::EmptyFrame);
    }
    if length > MAX_FRAME_BYTES {
        return Err(NativeWorkerError::FrameTooLarge {
            actual: length,
            maximum: MAX_FRAME_BYTES,
        });
    }
    let mut body = vec![0_u8; length as usize];
    input.read_exact(&mut body)?;
    Ok(Some(serde_json::from_slice(&body)?))
}

fn read_frame_from<R: Read>(reader: &mut R) -> Result<Option<WorkerFrame>, NativeWorkerError> {
    let mut prefix = [0_u8; 4];
    match reader.read_exact(&mut prefix) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(NativeWorkerError::Io(error)),
    }
    let length = u32::from_le_bytes(prefix);
    if length == 0 {
        return Err(NativeWorkerError::EmptyFrame);
    }
    if length > MAX_FRAME_BYTES {
        return Err(NativeWorkerError::FrameTooLarge {
            actual: length,
            maximum: MAX_FRAME_BYTES,
        });
    }
    let mut body = vec![0_u8; length as usize];
    reader.read_exact(&mut body)?;
    Ok(Some(serde_json::from_slice(&body)?))
}

fn write_frame_to<W: Write>(
    response: &WorkerResponse,
    writer: &mut W,
) -> Result<(), NativeWorkerError> {
    let body = serde_json::to_vec(response)?;
    let length = u32::try_from(body.len()).map_err(|_| NativeWorkerError::FrameTooLarge {
        actual: u32::MAX,
        maximum: MAX_FRAME_BYTES,
    })?;
    if length > MAX_FRAME_BYTES {
        return Err(NativeWorkerError::FrameTooLarge {
            actual: length,
            maximum: MAX_FRAME_BYTES,
        });
    }
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use eliot_cli::kernel_client::KernelClientError;

    use super::*;
    use crate::kernel_admission_client::kernel_admission_error;

    #[test]
    fn missing_session_bound_claim_is_typed_admission_failure() {
        let error = kernel_admission_error(&KernelClientError::MissingRequestIdentity);

        assert!(matches!(
            error,
            NativeWorkerError::KernelAdmissionRequired(detail)
                if detail == "kernel request identity is missing"
        ));
    }
}
