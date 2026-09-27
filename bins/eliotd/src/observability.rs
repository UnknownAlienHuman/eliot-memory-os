//! Process observability configuration for the `eliotd` composition root
//! (issue #1836 W1, I16.2).
//!
//! Every field is derived from a root this binary already resolves. Nothing
//! here invents a path, an endpoint, or a capacity: the two directories come
//! from the daemon's own protected-`ProgramData` constants
//! (`eliotd::PROTECTED_STATE_RELATIVE`, `Eliot\governor\state`, which
//! `eliotd::DaemonConfig::state_root` is), the profile is the installation
//! contour the daemon is launched into, and the capacities are the crate's own
//! declared ceilings.
//!
//! `eliotd` is the production Governor daemon and is installed and launched as
//! a Windows service by the Host, so its last-resort sink is the Windows Event
//! Log and no protected spool is configured — exactly the `system_service`
//! shape `eliot-observability-runtime::bootstrap::sinks_for` requires.

use std::path::{Path, PathBuf};

use eliot_observability_runtime::{ObservabilityConfig, RollingLogPolicy, RuntimeProfile};

/// Stable operational-log stem for this process. The generation name carries
/// the exit code, so a fresh process start is distinguishable from a rolling
/// rotation without any second naming scheme.
const OPERATIONAL_LOG_STEM: &str = "eliotd";

/// Bounded operational-log generation size, in bytes, at the crate's own
/// declared ceiling (`eliot_observability-runtime::config::MAX_ROLLING_BYTES`).
const OPERATIONAL_LOG_GENERATION_BYTES: u64 =
    eliot_observability_runtime::config::MAX_ROLLING_BYTES;

/// Bounded operational-log generation count, at the same declared ceiling.
const OPERATIONAL_LOG_GENERATIONS: u32 =
    eliot_observability_runtime::config::MAX_ROLLING_GENERATIONS;

/// Bounded writer-queue depth, in records, before admission starts dropping and
/// the visible dropped-records gauge advances (I16.11 forbids hidden loss), at
/// the crate's own declared ceiling.
const OPERATIONAL_LOG_QUEUED_RECORDS: usize =
    eliot_observability_runtime::config::MAX_ROLLING_QUEUED_RECORDS;

/// Returns the process observability configuration for this daemon.
#[must_use]
pub(super) fn daemon_config() -> ObservabilityConfig {
    ObservabilityConfig {
        profile: RuntimeProfile::SystemService,
        rolling_log: RollingLogPolicy {
            directory: state_root().join("logs"),
            file_stem: OPERATIONAL_LOG_STEM.to_owned(),
            max_bytes_per_generation: OPERATIONAL_LOG_GENERATION_BYTES,
            max_generations: OPERATIONAL_LOG_GENERATIONS,
            max_buffered_records: OPERATIONAL_LOG_QUEUED_RECORDS,
            exit_code: 0,
        },
        // `system_service` uses the Windows Event Log as its last resort, so
        // no protected spool is configured here.
        spool: None,
        // No canonical `OpenMetrics` bind address and no approved OTLP
        // collector endpoint exist in the tree, so both stay at the crate's
        // own disabled default; I16.2 requires the OTLP bridge to stay
        // disabled by default.
        metrics_listen: None,
        otlp_endpoint: None,
    }
}

/// The daemon's own protected state directory, resolved the same way
/// `eliotd::DaemonConfig` resolves it: the `ProgramData`-relative
/// `Eliot\governor\state` constant joined onto the OS-resolved protected
/// `ProgramData` root.
///
/// The daemon state root may be unreachable in a non-installed context (an
/// uninstalled dev shell cannot resolve `ProgramData`); the caller must not
/// depend on this succeeding.
fn state_root() -> PathBuf {
    eliot_platform_windows::protected_program_data_path(eliotd::PROTECTED_STATE_RELATIVE)
        .unwrap_or_else(|_| Path::new(eliotd::PROTECTED_STATE_RELATIVE).to_path_buf())
}
