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
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;

use tracing_subscriber::fmt::MakeWriter;

use crate::config::RollingLogPolicy;

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
    sender: SyncSender<String>,
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
        match self.sender.try_send(line.to_owned()) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped_records.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Records dropped by full-queue admission since process start.
    #[must_use]
    pub fn dropped_records(&self) -> u64 {
        self.dropped_records.load(Ordering::Relaxed)
    }
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
        let (sender, receiver) = sync_channel::<String>(policy.max_buffered_records);
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
    receiver: &Receiver<String>,
    shutdown_requested: &std::sync::Arc<AtomicBool>,
) -> u64 {
    let mut active = match open_generation(&generation_path(policy, 0)) {
        Ok(file) => ActiveGeneration {
            file,
            written: 0,
            index: 0,
        },
        Err(_) => return receiver.try_iter().count() as u64,
    };
    while let Ok(line) = receiver.recv() {
        let payload = format!("{line}\n");
        let size = u64::try_from(payload.len()).unwrap_or(u64::MAX);
        if active.written > 0
            && active.written.saturating_add(size) > policy.max_bytes_per_generation
        {
            rotate(&mut active, policy);
        }
        if active.file.write_all(payload.as_bytes()).is_ok() {
            active.written = active.written.saturating_add(size);
        }
        if shutdown_requested.load(Ordering::Acquire) {
            break;
        }
    }
    let _ = active.file.flush();
    receiver.try_iter().count() as u64
}

/// Starts the next generation and deletes generations past the retention
/// bound. A generation that cannot be opened leaves the active generation
/// receiving records rather than losing them, so a failed rotation is a
/// visible over-bound file and not a silent gap.
fn rotate(active: &mut ActiveGeneration, policy: &RollingLogPolicy) {
    let Some(next) = active.index.checked_add(1) else {
        return;
    };
    if let Ok(file) = open_generation(&generation_path(policy, next)) {
        let _ = active.file.flush();
        active.file = file;
        active.written = 0;
        active.index = next;
    } else {
        return;
    }
    let horizon = next
        .saturating_add(1)
        .saturating_sub(policy.max_generations);
    for index in 0..horizon {
        let _ = fs::remove_file(generation_path(policy, index));
    }
}

fn generation_path(policy: &RollingLogPolicy, index: u32) -> PathBuf {
    policy
        .directory
        .join(format!("{}.{index}", policy.file_stem))
}

fn open_generation(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}
