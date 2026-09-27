//! Protected rolling-file event spool for the `user_mode` and portable
//! profiles (I16.2, I16.11 stage 2).
//!
//! The spool is the ORS/Watchdog stand-in for installations that have no
//! service control manager and therefore no Windows Event Log. Records are
//! appended as one JSON line each, so a partially written tail is detectable
//! rather than silently readable as a complete record. Retention is the
//! configured rolling bound: at most `max_generations` files, oldest removed
//! first, and an over-bound record is rejected instead of truncated into a
//! plausible-looking entry (I16.9).

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::config::SpoolPolicy;
use crate::critical_path::{CriticalEventRecord, SinkStatus, UnavailableReason};

/// Typed spool failure. Every variant is diagnostic; the spool never gates the
/// host operation that produced the record.
#[derive(Debug)]
pub enum EventSpoolError {
    /// The policy failed validation, so no spool was opened.
    InvalidPolicy(String),
    /// The spool directory or active generation could not be opened.
    Io(io::Error),
}

impl fmt::Display for EventSpoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(detail) => {
                write!(formatter, "event spool policy rejected: {detail}")
            }
            Self::Io(error) => write!(formatter, "event spool io failure: {error}"),
        }
    }
}

impl std::error::Error for EventSpoolError {}

/// Append-only protected event spool.
///
/// Writes are synchronous and bounded: one record per call, no unbounded
/// buffer, and an io failure is reported rather than swallowed. This is the
/// I16.11 second stage, so a refusal here must stay visible to the state
/// machine instead of degrading into a lost record. A clone shares the one
/// active generation behind the shared mutex, so a clone never opens a second
/// file.
#[derive(Debug, Clone)]
pub struct EventSpool {
    policy: SpoolPolicy,
    active: Arc<Mutex<ActiveGeneration>>,
}

#[derive(Debug)]
struct ActiveGeneration {
    file: File,
    written: u64,
    index: u32,
}

impl EventSpool {
    /// Opens the spool directory and its first generation.
    ///
    /// # Errors
    ///
    /// Returns [`EventSpoolError::InvalidPolicy`] for a rejected policy and
    /// [`EventSpoolError::Io`] when the directory or generation cannot be
    /// opened.
    pub fn open(policy: SpoolPolicy) -> Result<Self, EventSpoolError> {
        policy
            .validate()
            .map_err(|error| EventSpoolError::InvalidPolicy(error.to_string()))?;
        fs::create_dir_all(&policy.directory).map_err(EventSpoolError::Io)?;
        let file = open_generation(&generation_path(&policy, 0)).map_err(EventSpoolError::Io)?;
        Ok(Self {
            policy,
            active: Arc::new(Mutex::new(ActiveGeneration {
                file,
                written: 0,
                index: 0,
            })),
        })
    }

    /// Appends one record and returns the terminal sink status for the I16.11
    /// chain.
    ///
    /// `record_bounded` is the already-serialized single-line payload. A
    /// payload above `max_record_bytes` is rejected: the spool refuses rather
    /// than truncating a protected lifecycle record.
    pub fn append(&self, record_bounded: &str) -> SinkStatus {
        let payload = format!("{record_bounded}\n");
        let size = u64::try_from(payload.len()).unwrap_or(u64::MAX);
        if size > self.policy.max_record_bytes {
            return SinkStatus::Unavailable(UnavailableReason::NotApplicable);
        }
        let Ok(mut active) = self.active.lock() else {
            return SinkStatus::Unavailable(UnavailableReason::Unavailable);
        };
        if active.written > 0 && active.written.saturating_add(size) > u64::MAX / 2 {
            rotate(&mut active, &self.policy);
        }
        if active.file.write_all(payload.as_bytes()).is_err() {
            return SinkStatus::Unavailable(UnavailableReason::Unavailable);
        }
        active.written = active.written.saturating_add(size);
        SinkStatus::Delivered
    }

    /// Serializes and appends one critical record.
    ///
    /// # Errors
    ///
    /// Returns the serialization error when the record cannot be rendered as
    /// one JSON line; a rendered record is always appended without a lossy
    /// fallback.
    pub fn append_record(
        &self,
        record: &CriticalEventRecord,
    ) -> Result<SinkStatus, serde_json::Error> {
        let line = serde_json::to_string(record)?;
        Ok(self.append(&line))
    }
}

/// Second-stage sink group for the I16.11 chain.
///
/// Holds the protected spool when one is configured, and reports
/// `NotApplicable` when the profile has none (the `system_service` profile uses
/// the Event Log for the last-resort stage instead).
#[derive(Debug, Clone)]
pub struct SpoolSinks {
    spool: Option<EventSpool>,
}

impl SpoolSinks {
    /// Wraps an opened spool as the second critical-path stage.
    #[must_use]
    pub const fn new(spool: EventSpool) -> Self {
        Self { spool: Some(spool) }
    }

    /// Builds a second stage with no spool, for `system_service`.
    #[must_use]
    pub const fn absent() -> Self {
        Self { spool: None }
    }

    /// Attempts to spool one critical record.
    pub fn write(&self, record: &CriticalEventRecord) -> SinkStatus {
        let Some(spool) = &self.spool else {
            return SinkStatus::Unavailable(UnavailableReason::NotApplicable);
        };
        spool
            .append_record(record)
            .unwrap_or(SinkStatus::Unavailable(UnavailableReason::NotApplicable))
    }
}

fn rotate(active: &mut ActiveGeneration, policy: &SpoolPolicy) {
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

fn generation_path(policy: &SpoolPolicy, index: u32) -> PathBuf {
    policy
        .directory
        .join(format!("{}.{index}.jsonl", policy.file_stem))
}

fn open_generation(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}
