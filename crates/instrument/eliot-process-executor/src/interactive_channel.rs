//! Interactive child stdio channel over P-04 owned operations (issue #1941).
//!
//! Implements [`InteractiveChildChannel`](eliot_process::InteractiveChildChannel)
//! for [`WindowsProcessExecutor`](super::WindowsProcessExecutor) against the
//! exact operation registry: stdin writes go to the retained handle taken
//! at capture setup (interactive opt-in only), stdout reads serve the
//! stdout capture session's retained prefix through a per-operation
//! monotonic offset. One drain owns the pipe; the channel never competes
//! with it — reads observe the session, they do not re-drain.
//!
//! Lifecycle: the stdin handle dies with the operation struct (terminal
//! cleanup, cancel finalization, and drop all release it; cancel keeps the
//! typed `CancelledBeforeEof`/`UnknownOutcome` evidence, which reads map
//! without touching a dead pipe). Locking never nests operation inside
//! session across waits: each step snapshots under brief guards, and the
//! only wait (bounded poll sleep) holds no lock, so cancel/inspect stay
//! available for the operation while a channel read is outstanding.

use std::io::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eliot_process::{
    ChildStdoutChunk, ContractError, InteractiveChildChannel, MAX_CHILD_STDIN_WRITE_BYTES,
    OperationId, ProcessExecutionError,
};

use super::{CaptureDisposition, WindowsProcessExecutor, operation_unavailable};

/// Bounded poll pause inside a channel read wait: spurious wakeups retry
/// within the caller deadline instead of spinning.
const CHANNEL_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Resolves one registered operation or fails closed as unknown.
fn operation_arc(
    executor: &WindowsProcessExecutor,
    operation_id: &OperationId,
) -> Result<Arc<std::sync::Mutex<super::Operation>>, ProcessExecutionError> {
    executor.operation(operation_id)
}

impl InteractiveChildChannel for WindowsProcessExecutor {
    fn write_child_stdin(
        &self,
        operation_id: OperationId,
        bytes: Vec<u8>,
    ) -> eliot_process::InteractiveChildFuture<'_, usize> {
        Box::pin(async move {
            if bytes.len() > MAX_CHILD_STDIN_WRITE_BYTES {
                return Err(ProcessExecutionError::Contract(
                    ContractError::LimitExceeded {
                        field: "stdin_write_bytes",
                        limit: MAX_CHILD_STDIN_WRITE_BYTES,
                    },
                ));
            }
            let operation = operation_arc(self, &operation_id)?;
            let mut guard = operation
                .lock()
                .map_err(|_| operation_unavailable(&operation_id, "operation lock"))?;
            let Some(stdin) = guard.stdin.as_mut() else {
                return Err(ProcessExecutionError::Unavailable(
                    "interactive stdin not retained".to_owned(),
                ));
            };
            stdin
                .write_all(&bytes)
                .map_err(|_| ProcessExecutionError::Unavailable("stdin write failed".to_owned()))?;
            Ok(bytes.len())
        })
    }

    fn read_child_stdout(
        &self,
        operation_id: &OperationId,
        max_bytes: usize,
        deadline: Duration,
    ) -> eliot_process::InteractiveChildFuture<'_, ChildStdoutChunk> {
        // Own the identity for the whole wait: the returned future must
        // outlive the caller's borrow.
        let operation_id = operation_id.clone();
        Box::pin(async move {
            let started = Instant::now();
            loop {
                let operation = operation_arc(self, &operation_id)?;
                // Snapshot under brief guards; no nesting across waits.
                let (session, offset) = {
                    let guard = operation
                        .lock()
                        .map_err(|_| operation_unavailable(&operation_id, "operation lock"))?;
                    (Arc::clone(&guard.stdout), guard.channel_read_offset)
                };
                let (bytes, new_offset, end_of_stream) = {
                    let session_guard = session
                        .lock()
                        .map_err(|_| operation_unavailable(&operation_id, "capture lock"))?;
                    if session_guard.truncated() {
                        return Err(ProcessExecutionError::Unavailable(
                            "capture truncated".to_owned(),
                        ));
                    }
                    match session_guard.disposition() {
                        CaptureDisposition::ReadFailed => {
                            return Err(ProcessExecutionError::Unavailable(
                                "capture read failed".to_owned(),
                            ));
                        }
                        CaptureDisposition::CancelledBeforeEof
                        | CaptureDisposition::UnknownOutcome => {
                            return Err(ProcessExecutionError::UnknownOutcome);
                        }
                        CaptureDisposition::CaptureUnavailable => {
                            return Err(ProcessExecutionError::Unavailable(
                                "capture unavailable".to_owned(),
                            ));
                        }
                        CaptureDisposition::Draining | CaptureDisposition::Eof => {}
                    }
                    let prefix = session_guard.prefix();
                    let total = prefix.len();
                    let start_at = offset.min(total);
                    let available = total - start_at;
                    let take = available.min(max_bytes);
                    let end_of_stream =
                        matches!(session_guard.disposition(), CaptureDisposition::Eof)
                            && start_at + take >= total;
                    (
                        prefix[start_at..start_at + take].to_vec(),
                        start_at + take,
                        end_of_stream,
                    )
                };
                {
                    let mut guard = operation
                        .lock()
                        .map_err(|_| operation_unavailable(&operation_id, "operation lock"))?;
                    guard.channel_read_offset = guard.channel_read_offset.max(new_offset);
                }
                if !bytes.is_empty() || end_of_stream {
                    return Ok(ChildStdoutChunk {
                        bytes,
                        end_of_stream,
                    });
                }
                if started.elapsed() >= deadline {
                    return Ok(ChildStdoutChunk {
                        bytes: Vec::new(),
                        end_of_stream: false,
                    });
                }
                std::thread::sleep(CHANNEL_POLL_INTERVAL);
            }
        })
    }
}
