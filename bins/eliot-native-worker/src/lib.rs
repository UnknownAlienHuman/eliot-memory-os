//! Thin composition boundary for one isolated native-worker generation.
//!
//! The binary owns framing and process lifetime only. Admission, process
//! execution, evidence, replay, and checkpoint persistence remain injected
//! ports owned by the governing services.

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};

use eliot_native_worker_core::{
    WorkerCore, WorkerError, WorkerEventEnvelope, WorkerFrame, WorkerHello, WorkerLifecycle,
};
use eliot_process::{ProcessExecutor, ProcessRequest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;

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

    /// Handles one already-decoded EBP worker frame.
    pub async fn handle(
        &mut self,
        frame: WorkerFrame,
    ) -> Result<Vec<WorkerEventEnvelope>, NativeWorkerError> {
        self.core.handle(frame).await.map_err(NativeWorkerError::from)
    }

    /// Returns the logical lifecycle owned by the worker protocol.
    #[must_use]
    pub const fn lifecycle(&self) -> WorkerLifecycle {
        self.core.lifecycle()
    }

    /// Serves length-delimited JSON frames after the caller has completed start.
    pub async fn serve_stdio(&mut self) -> Result<(), NativeWorkerError> {
        loop {
            let frame = match read_frame()? {
                Some(frame) => frame,
                None => return Ok(()),
            };
            let shutdown = matches!(frame.body, eliot_native_worker_core::WorkerFrameBody::Shutdown);
            let events = self.handle(frame).await?;
            write_frame(&WorkerResponse { events })?;
            if shutdown {
                return Ok(());
            }
        }
    }
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

fn write_frame(response: &WorkerResponse) -> Result<(), NativeWorkerError> {
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
    let mut output = io::stdout().lock();
    output.write_all(&length.to_le_bytes())?;
    output.write_all(&body)?;
    output.flush()?;
    Ok(())
}
