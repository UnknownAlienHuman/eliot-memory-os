//! Bounded observability configuration (I16.2, I16.9).
//!
//! Every capacity here is finite on purpose: I16.9 states that telemetry
//! consumes the same CPU, memory, I/O, queue and storage it observes, so an
//! unbounded buffer is itself a defect. [`ObservabilityConfig::validate`]
//! refuses zero and over-bound capacities rather than silently starting an
//! unbounded sink.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Largest accepted rolling generation count. One generation per log file
/// bounds disk growth to `max_generations * max_bytes_per_generation`.
pub const MAX_ROLLING_GENERATIONS: u32 = 64;

/// Largest accepted rolling generation size, in bytes.
pub const MAX_ROLLING_BYTES: u64 = 64 * 1024 * 1024;

/// Largest accepted rolling writer-queue depth, in records, before admission
/// starts dropping and the visible dropped-records gauge advances.
pub const MAX_ROLLING_QUEUED_RECORDS: usize = 1024;

/// Largest accepted `OpenMetrics` series cardinality.
///
/// I16.1 requires bounded metric labels; the family-wide bound below is the
/// guard that keeps a single scrape from reconstructing content.
pub const MAX_METRIC_SERIES: usize = 4096;

/// Largest accepted metric label count per series.
pub const MAX_METRIC_LABELS: usize = 8;

/// Largest accepted metric label value length, in characters.
pub const MAX_METRIC_LABEL_CHARS: usize = 128;

/// Largest accepted usage/cost bucket count.
///
/// I16.5 stores usage and cost facts separately from the metric registry, and
/// I16.9 states that telemetry consumes the same CPU, memory, I/O, queue and
/// context resources it observes, so that separate store is bounded too rather
/// than growing with the number of routes in flight. The bound admits the full
/// cross product of the closed scope, truth and work-class vocabularies for
/// several concurrent routes: three scopes times five truth levels times nine
/// work classes is 135 buckets, so 1024 leaves room for several routes before a
/// new bucket is refused visibly.
pub const MAX_USAGE_COST_BUCKETS: usize = 1024;

/// Largest accepted usage/cost identifier value, in characters.
///
/// A provider identity in the separately stored usage/cost facts is a bounded
/// name, not a URL carrying a credential and not free text, so it is held to the
/// same bound discipline as a metric label value.
pub const MAX_USAGE_COST_ID_CHARS: usize = 128;

/// Largest accepted spooled critical-event record, in bytes.
pub const MAX_SPOOL_RECORD_BYTES: u64 = 8 * 1024;

/// Largest accepted crash-report document, in bytes.
pub const MAX_CRASH_REPORT_BYTES: u64 = 1024 * 1024;

/// Typed configuration rejection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ObservabilityConfigError {
    /// A capacity is zero or above its declared ceiling.
    #[error("observability bound {field} must be within 1..={max}")]
    OutOfBound {
        /// Stable field path.
        field: &'static str,
        /// Declared inclusive ceiling.
        max: u64,
    },
    /// The profile and the requested sink set are inconsistent.
    #[error("observability configuration is inconsistent: {0}")]
    Inconsistent(&'static str),
}

/// Which installation profile the running process serves.
///
/// I16.2 splits the last-resort sink by profile: `system_service` uses the
/// Windows Event Log, `user_mode` and portable use the protected rolling-file
/// event spool. The profile is an installation fact supplied by the caller;
/// this crate never infers it from environment, path, port, or PID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProfile {
    /// Installed as a Windows service under the protected installation root.
    SystemService,
    /// Running interactively for one signed-in user.
    UserMode,
    /// Portable root: no installer, no service control manager, no Event Log.
    Portable,
}

impl RuntimeProfile {
    /// Stable profile name carried in crash and critical-event records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemService => "system_service",
            Self::UserMode => "user_mode",
            Self::Portable => "portable",
        }
    }
}

/// Rolling retention policy for operational logs (I16.9 `operational logs:
/// rolling policy`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollingLogPolicy {
    /// Directory holding the rolling generations.
    pub directory: PathBuf,
    /// Stable log file stem; generations are `<stem>.0`, `<stem>.1`, …
    pub file_stem: String,
    /// Bytes written before a new generation is started.
    pub max_bytes_per_generation: u64,
    /// Retained generations, including the active one.
    pub max_generations: u32,
    /// Bound on records buffered for the writer thread before records are
    /// dropped with a visible dropped-records count.
    pub max_buffered_records: usize,
    /// Process exit code appended to the active generation name; distinguishes
    /// a rolling rotation from a fresh process start.
    pub exit_code: u32,
}

impl RollingLogPolicy {
    /// Validates the rolling bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ObservabilityConfigError::OutOfBound`] for a zero or
    /// over-ceiling capacity and [`ObservabilityConfigError::Inconsistent`]
    /// for a blank file stem.
    pub fn validate(&self) -> Result<(), ObservabilityConfigError> {
        bounded(
            "max_bytes_per_generation",
            self.max_bytes_per_generation,
            MAX_ROLLING_BYTES,
        )?;
        bounded_u32(
            "max_generations",
            self.max_generations,
            MAX_ROLLING_GENERATIONS,
        )?;
        if self.max_buffered_records == 0 || self.max_buffered_records > MAX_ROLLING_QUEUED_RECORDS
        {
            return Err(ObservabilityConfigError::OutOfBound {
                field: "max_buffered_records",
                max: MAX_ROLLING_QUEUED_RECORDS as u64,
            });
        }
        if self.file_stem.trim().is_empty() {
            return Err(ObservabilityConfigError::Inconsistent(
                "rolling log file_stem must be non-blank",
            ));
        }
        Ok(())
    }
}

/// Retention policy for the protected file/event spool used as the
/// `user_mode` and portable last-resort surface (I16.9).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpoolPolicy {
    /// Protected directory holding the append-only spool.
    pub directory: PathBuf,
    /// Stable spool file stem.
    pub file_stem: String,
    /// Retained spool generations, including the active one.
    pub max_generations: u32,
    /// Largest accepted single record, in bytes. An over-bound record is
    /// rejected, never truncated into a plausible-looking record.
    pub max_record_bytes: u64,
}

impl SpoolPolicy {
    /// Validates the spool bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ObservabilityConfigError::OutOfBound`] for a zero or
    /// over-ceiling capacity.
    pub fn validate(&self) -> Result<(), ObservabilityConfigError> {
        bounded_u32(
            "max_generations",
            self.max_generations,
            MAX_ROLLING_GENERATIONS,
        )?;
        bounded(
            "max_record_bytes",
            self.max_record_bytes,
            MAX_SPOOL_RECORD_BYTES,
        )?;
        if self.file_stem.trim().is_empty() {
            return Err(ObservabilityConfigError::Inconsistent(
                "spool file_stem must be non-blank",
            ));
        }
        Ok(())
    }
}

/// Whole-runtime observability configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    /// Installation profile deciding the last-resort sink.
    pub profile: RuntimeProfile,
    /// Rolling operational-log policy.
    pub rolling_log: RollingLogPolicy,
    /// Protected event-spool policy; required for `user_mode` and portable.
    pub spool: Option<SpoolPolicy>,
    /// `OpenMetrics` listen address; `None` disables the endpoint.
    pub metrics_listen: Option<String>,
    /// OTLP collector endpoint. Honoured only when the `otlp` feature is built.
    pub otlp_endpoint: Option<String>,
}

impl ObservabilityConfig {
    /// Validates every bound and the profile/sink consistency rule.
    ///
    /// # Errors
    ///
    /// Returns [`ObservabilityConfigError::OutOfBound`] for an out-of-range
    /// capacity and [`ObservabilityConfigError::Inconsistent`] when the
    /// profile requires a sink the configuration omits.
    pub fn validate(&self) -> Result<(), ObservabilityConfigError> {
        self.rolling_log.validate()?;
        match &self.spool {
            Some(spool) => spool.validate()?,
            None if !matches!(self.profile, RuntimeProfile::SystemService) => {
                return Err(ObservabilityConfigError::Inconsistent(
                    "user_mode and portable profiles require a protected event spool",
                ));
            }
            None => {}
        }
        Ok(())
    }

    /// The directory this configuration writes operational output into.
    #[must_use]
    pub fn log_directory(&self) -> &Path {
        &self.rolling_log.directory
    }
}

fn bounded(field: &'static str, value: u64, max: u64) -> Result<(), ObservabilityConfigError> {
    if value == 0 || value > max {
        return Err(ObservabilityConfigError::OutOfBound { field, max });
    }
    Ok(())
}

fn bounded_u32(field: &'static str, value: u32, max: u32) -> Result<(), ObservabilityConfigError> {
    bounded(field, u64::from(value), u64::from(max))
}
