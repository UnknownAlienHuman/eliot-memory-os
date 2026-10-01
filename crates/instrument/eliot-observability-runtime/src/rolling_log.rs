//! Non-blocking rolling operational-log appender (I16.2, I16.9).
//!
//! Producers never touch the filesystem. [`RollingLogWriter::try_send`] hands
//! one formatted line to a bounded queue and returns immediately; one
//! dedicated thread owns every file operation. A full queue drops the record
//! and advances a monotone [`RollingLogWriter::dropped_records`] counter that
//! the bootstrap publishes as a metric, so back-pressure can never become
//! hidden loss (I16.11).
//!
//! Retention is exactly the configured rolling policy: at most
//! `max_generations` files of at most `max_bytes_per_generation` bytes each,
//! oldest deleted first. There is no compression pass and no second thread.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::thread::JoinHandle;

use tracing_subscriber::fmt::MakeWriter;

use crate::config::{MAX_ROLLING_BYTES, RollingLogPolicy};

/// Typed appender failure. Every variant is diagnostic: the operational log
/// never gates the host operation that produced the record.
#[derive(Debug)]
pub enum RollingLogError {
    /// The policy failed validation, so no appender was created.
    InvalidPolicy(String),
    /// The log directory or active generation could not be created.
    Io(io::Error),
}

impl fmt::Display for RollingLogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(detail) => {
                write!(formatter, "rolling log policy rejected: {detail}")
            }
            Self::Io(error) => write!(formatter, "rolling log io failure: {error}"),
        }
    }
}

impl std::error::Error for RollingLogError {}

/// Non-blocking producer side of the rolling appender.
///
/// Cheap to clone: every clone shares the one writer thread, the one bounded
/// queue, and the one drop counter.
#[derive(Clone, Debug)]
pub struct RollingLogWriter {
    sender: SyncSender<RollingLogRecord>,
    dropped_records: std::sync::Arc<AtomicU64>,
    shutdown_requested: std::sync::Arc<AtomicBool>,
}

impl RollingLogWriter {
    /// Enqueues one already-formatted record without blocking.
    ///
    /// Returns `false` when the bounded queue is full or the writer thread has
    /// stopped; the record is dropped and the visible drop counter advances.
    /// Callers must treat `false` as lost observability, never as a
    /// successful write.
    pub fn try_send(&self, line: &str) -> bool {
        if self.shutdown_requested.load(Ordering::Acquire) {
            self.dropped_records.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        match self.sender.try_send(RollingLogRecord {
            line: line.to_owned(),
            acknowledgement: None,
        }) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped_records.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Enqueues one already-formatted record and returns a bounded receipt
    /// channel for its append/retention result. Queue admission remains
    /// nonblocking; only the caller's separate receipt wait may block.
    pub fn try_send_with_ack(
        &self,
        line: &str,
    ) -> Result<Receiver<RollingLogAppendOutcome>, RollingLogAppendError> {
        if u64::try_from(line.len().saturating_add(1)).unwrap_or(u64::MAX) > MAX_ROLLING_BYTES {
            return Err(RollingLogAppendError::OverBound);
        }
        if self.shutdown_requested.load(Ordering::Acquire) {
            self.dropped_records.fetch_add(1, Ordering::Relaxed);
            return Err(RollingLogAppendError::WriterUnavailable);
        }
        let (ack_sender, ack_receiver) = sync_channel(1);
        let record = RollingLogRecord {
            line: line.to_owned(),
            acknowledgement: Some(ack_sender),
        };
        match self.sender.try_send(record) {
            Ok(()) => Ok(ack_receiver),
            Err(TrySendError::Full(_)) => {
                self.dropped_records.fetch_add(1, Ordering::Relaxed);
                Err(RollingLogAppendError::QueueFull)
            }
            Err(TrySendError::Disconnected(_)) => {
                self.dropped_records.fetch_add(1, Ordering::Relaxed);
                Err(RollingLogAppendError::WriterUnavailable)
            }
        }
    }

    /// Records dropped by full-queue admission since process start.
    #[must_use]
    pub fn dropped_records(&self) -> u64 {
        self.dropped_records.load(Ordering::Relaxed)
    }
}

/// Durable outcome returned by the rolling writer for one acknowledged line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollingLogAppendOutcome {
    /// The line was appended and configured generation retention succeeded.
    Written,
    /// The line was refused or configured generation retention failed.
    RetentionFailure,
    /// The line could not be written because file I/O failed.
    StorageFailure,
}

/// Nonblocking queue-admission failure for an acknowledged line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollingLogAppendError {
    /// The line itself exceeds the global accepted generation ceiling.
    OverBound,
    /// The configured writer queue was full.
    QueueFull,
    /// The writer has stopped or is unavailable.
    WriterUnavailable,
}

struct RollingLogRecord {
    line: String,
    acknowledgement: Option<SyncSender<RollingLogAppendOutcome>>,
}

/// Adapts the non-blocking appender to `tracing_subscriber`'s `MakeWriter`, so
/// the rolling layer performs the bounded non-blocking enqueue and never
/// touches the filesystem on the emitting thread.
impl<'a> MakeWriter<'a> for RollingLogWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl Write for RollingLogWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.try_send(&String::from_utf8_lossy(buffer)) {
            Ok(buffer.len())
        } else {
            Err(io::Error::other("rolling log queue is full or closed"))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Joinable owner of the single process-wide appender thread.
#[derive(Debug)]
pub struct RollingLogHandle {
    writer: RollingLogWriter,
    worker: Option<JoinHandle<u64>>,
}

impl RollingLogHandle {
    /// Creates the log directory, opens the first generation, and starts the
    /// one writer thread.
    ///
    /// # Errors
    ///
    /// Returns [`RollingLogError::InvalidPolicy`] for a rejected policy and
    /// [`RollingLogError::Io`] when the directory, thread, or generation
    /// cannot be created.
    pub fn start(policy: &RollingLogPolicy) -> Result<Self, RollingLogError> {
        policy
            .validate()
            .map_err(|error| RollingLogError::InvalidPolicy(error.to_string()))?;
        fs::create_dir_all(&policy.directory).map_err(RollingLogError::Io)?;
        let (sender, receiver) = sync_channel::<RollingLogRecord>(policy.max_buffered_records);
        let shutdown_requested = std::sync::Arc::new(AtomicBool::new(false));
        let thread_flag = std::sync::Arc::clone(&shutdown_requested);
        let worker = std::thread::Builder::new()
            .name("eliot-observability-log".to_owned())
            .spawn({
                let policy = policy.clone();
                let flag = std::sync::Arc::clone(&thread_flag);
                move || run_writer(&policy, &receiver, &flag)
            })
            .map_err(RollingLogError::Io)?;
        Ok(Self {
            writer: RollingLogWriter {
                sender,
                dropped_records: std::sync::Arc::new(AtomicU64::new(0)),
                shutdown_requested,
            },
            worker: Some(worker),
        })
    }

    /// The non-blocking producer side.
    #[must_use]
    pub fn writer(&self) -> RollingLogWriter {
        self.writer.clone()
    }

    /// Asks the writer thread to stop and reports the honest terminal view.
    ///
    /// `unsent` counts records still queued when the thread stopped: they were
    /// neither written nor proven written, so no drain is claimed.
    #[must_use]
    pub fn shutdown(mut self) -> RollingLogShutdown {
        self.writer
            .shutdown_requested
            .store(true, Ordering::Release);
        let unsent = self
            .worker
            .take()
            .and_then(|worker| worker.join().ok())
            .unwrap_or_default();
        RollingLogShutdown {
            unsent,
            dropped_records: self.writer.dropped_records(),
        }
    }
}

impl Drop for RollingLogHandle {
    fn drop(&mut self) {
        self.writer
            .shutdown_requested
            .store(true, Ordering::Release);
    }
}

/// Terminal view of the appender taken after the writer thread is joined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollingLogShutdown {
    /// Records still queued when the writer thread stopped.
    pub unsent: u64,
    /// Records dropped by full-queue admission since process start.
    pub dropped_records: u64,
}

struct ActiveGeneration {
    file: File,
    written: u64,
    index: u32,
}

fn run_writer(
    policy: &RollingLogPolicy,
    receiver: &Receiver<RollingLogRecord>,
    shutdown_requested: &std::sync::Arc<AtomicBool>,
) -> u64 {
    let mut active = match open_generation(&generation_path(policy, 0)) {
        Ok(file) => match file.metadata() {
            Ok(metadata) => ActiveGeneration {
                file,
                written: metadata.len(),
                index: 0,
            },
            Err(_) => return reject_queued(receiver, RollingLogAppendOutcome::StorageFailure),
        },
        Err(_) => return reject_queued(receiver, RollingLogAppendOutcome::StorageFailure),
    };
    while let Ok(record) = receiver.recv() {
        let payload = format!("{}\n", record.line);
        let size = u64::try_from(payload.len()).unwrap_or(u64::MAX);
        let mut retention_failed = false;
        let mut write_allowed = true;
        let mut outcome = if size > policy.max_bytes_per_generation {
            RollingLogAppendOutcome::RetentionFailure
        } else {
            RollingLogAppendOutcome::Written
        };
        if outcome == RollingLogAppendOutcome::Written
            && active.written.saturating_add(size) > policy.max_bytes_per_generation
        {
            let mut rotations = 0_u32;
            while active.written.saturating_add(size) > policy.max_bytes_per_generation
                && rotations <= policy.max_generations
            {
                match rotate(&mut active, policy) {
                    Ok(retention_ok) => retention_failed |= !retention_ok,
                    Err(_) => {
                        retention_failed = true;
                        if record.acknowledgement.is_some() {
                            write_allowed = false;
                        }
                        break;
                    }
                }
                rotations = rotations.saturating_add(1);
            }
            if active.written.saturating_add(size) > policy.max_bytes_per_generation {
                outcome = RollingLogAppendOutcome::RetentionFailure;
                if record.acknowledgement.is_some() {
                    write_allowed = false;
                }
            }
        }
        if write_allowed {
            if active.file.write_all(payload.as_bytes()).is_ok() {
                active.written = active.written.saturating_add(size);
                if retention_failed || outcome == RollingLogAppendOutcome::Written
                    && active.written > policy.max_bytes_per_generation
                {
                    outcome = RollingLogAppendOutcome::RetentionFailure;
                }
            } else {
                outcome = RollingLogAppendOutcome::StorageFailure;
            }
        }
        if let Some(acknowledgement) = record.acknowledgement {
            let _ = acknowledgement.try_send(outcome);
        }
        if shutdown_requested.load(Ordering::Acquire) {
            break;
        }
    }
    let _ = active.file.flush();
    reject_queued(receiver, RollingLogAppendOutcome::StorageFailure)
}

fn reject_queued(
    receiver: &Receiver<RollingLogRecord>,
    outcome: RollingLogAppendOutcome,
) -> u64 {
    let mut unsent = 0_u64;
    loop {
        match receiver.try_recv() {
            Ok(record) => {
                if let Some(acknowledgement) = record.acknowledgement {
                    let _ = acknowledgement.try_send(outcome);
                }
                unsent = unsent.saturating_add(1);
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => return unsent,
        }
    }
}

/// Starts the next generation and deletes generations past the retention
/// bound. A generation that cannot be opened leaves the active generation
/// receiving records rather than losing them, so a failed rotation is a
/// visible over-bound file and not a silent gap.
fn rotate(active: &mut ActiveGeneration, policy: &RollingLogPolicy) -> io::Result<bool> {
    let next = active
        .index
        .checked_add(1)
        .ok_or_else(|| io::Error::other("rolling generation index overflow"))?;
    active.file.flush()?;
    let file = open_generation(&generation_path(policy, next))?;
    let written = file.metadata()?.len();
    active.file = file;
    active.written = written;
    active.index = next;
    let horizon = next
        .saturating_add(1)
        .saturating_sub(policy.max_generations);
    let mut retention_ok = true;
    for index in 0..horizon {
        if let Err(error) = fs::remove_file(generation_path(policy, index))
            && error.kind() != io::ErrorKind::NotFound
        {
            retention_ok = false;
        }
    }
    Ok(retention_ok)
}

fn generation_path(policy: &RollingLogPolicy, index: u32) -> PathBuf {
    policy
        .directory
        .join(format!("{}.{index}", policy.file_stem))
}

fn open_generation(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}
