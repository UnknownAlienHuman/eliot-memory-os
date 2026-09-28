//! Process-wide observability bootstrap (I16.2).
//!
//! One call from a bundle binary's `main` installs the whole stack:
//!
//! 1. structured `tracing` with bounded fields, writing JSON operational
//!    records to the non-blocking rolling appender and to stderr;
//! 2. the bounded-label `OpenMetrics` registry published for scraping;
//! 3. the OTLP bridge: `enabled` when a usable endpoint is configured and the
//!    `otlp` feature is built, `feature_disabled` when the feature is off,
//!    `endpoint_unusable` when the configured endpoint cannot be parsed, and
//!    `not_configured` when no endpoint is set - and, only in the first case,
//!    the export of this stack's own startup record through the bridge;
//! 4. the `system_service` Windows Event Log stage, or the protected event
//!    spool for `user_mode` and portable;
//! 5. the I16.11 critical-path fallback machine.
//!
//! Installation is idempotent and never gates startup. A second call returns
//! [`ObservabilityInstallOutcome::AlreadyInstalled`] with the first owner's
//! live handles, so a caller can report the real state instead of assuming
//! success.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

use crate::config::{ObservabilityConfig, ObservabilityConfigError, RuntimeProfile};
use crate::critical_path::{
    CriticalEventSinks, CriticalEventSinksEntry, CriticalPath, SinkStatus, UnavailableReason,
};
use crate::event_log::EventLogReport;
use crate::metrics::{Metric, MetricKind, OpenMetrics};
use crate::otlp::{OtlpBridge, OtlpBridgeError, OtlpDisposition, OtlpExport, otlp_enabled};
use crate::rolling_log::{RollingLogHandle, RollingLogWriter};
use crate::spool::{EventSpool, SpoolSinks};

/// Target every runtime record carries.
pub const OBSERVABILITY_TARGET: &str = "eliot_observability";

/// Metric name of the rolling appender's dropped-record gauge.
pub const DROPPED_LOG_RECORDS_METRIC: &str = "eliot_observability_dropped_log_records";

/// Metric name of the critical-path control-loss counter.
pub const CONTROL_LOSS_METRIC: &str = "eliot_observability_control_loss_total";

/// Metric name of the held control-loss record gauge.
pub const CONTROL_LOSS_HELD_METRIC: &str = "eliot_observability_control_loss_held";

/// Stable event name of the record an enabled OTLP bridge exports at install.
///
/// I16.4 requires process start to be visible; this is the observability
/// stack's own start, and it is the only record the bootstrap produces itself.
const OTLP_STARTUP_EVENT: &str = "observability.startup";

/// Shared bounded metric registry.
#[derive(Debug, Default)]
pub struct MetricsRegistry(Mutex<OpenMetrics>);

impl MetricsRegistry {
    /// Records one bounded sample, discarding a poisoned registry rather than
    /// panicking on the diagnostic path.
    pub fn record(&self, metric: &Metric<'_>) {
        if let Ok(mut registry) = self.0.lock() {
            let _ = registry.record(metric);
        }
    }

    /// Runs one bounded edit of the shared registry under its own lock.
    ///
    /// [`crate::ExecutionPathMetrics`] and the other catalogue helpers record
    /// through `&mut OpenMetrics`, and the registry's inner value is private, so
    /// without this accessor a caller that owns the sanctioned recorders could
    /// only build a *second* registry - and a scrape served from it would never
    /// carry a single execution-path series. This is the seam that keeps ONE
    /// registry: the edit runs under the same lock the served exposition is
    /// rendered from, so a sample recorded through it is immediately visible to
    /// [`Self::expose`] and to the installed exporter.
    ///
    /// A poisoned registry yields `None` rather than panicking on the diagnostic
    /// path; the caller reports the refusal instead of inventing a sample.
    pub fn with_open_metrics<R>(&self, edit: impl FnOnce(&mut OpenMetrics) -> R) -> Option<R> {
        self.0.lock().ok().map(|mut registry| edit(&mut registry))
    }

    /// Renders the current `OpenMetrics` exposition.
    #[must_use]
    pub fn expose(&self) -> String {
        self.0
            .lock()
            .map_or_else(|_| String::new(), |registry| registry.expose())
    }
}

/// Live handles to the installed observability stack.
#[derive(Clone, Debug)]
pub struct ObservabilityInstall {
    /// Non-blocking rolling-log producer.
    pub log: RollingLogWriter,
    /// Shared bounded metric registry.
    pub metrics: Arc<MetricsRegistry>,
    /// I16.11 critical-path fallback machine.
    pub critical_path: CriticalPath,
    /// Honest OTLP bridge disposition for this build. `Enabled` means an
    /// endpoint is configured and this build has the `otlp` feature, so a
    /// transport exists; it never claims that any particular export was
    /// accepted, which only the collector's response decides.
    pub otlp: OtlpDisposition,
    /// The live bridge, present only when `otlp` is `Enabled`. Absent otherwise,
    /// so a default build holds no bridge and can open no collector connection.
    pub otlp_bridge: Option<OtlpBridge>,
    /// Installation profile the stack was configured with.
    pub profile: RuntimeProfile,
}

impl ObservabilityInstall {
    /// Publishes the appender's dropped-record count and the critical-path
    /// control-loss gauges into the scrape, so a scrape is never a success
    /// indication while telemetry is being lost.
    pub fn publish_runtime_counters(&self) {
        self.metrics.record(&Metric::new(
            DROPPED_LOG_RECORDS_METRIC,
            MetricKind::Gauge,
            "operational log records dropped by bounded-queue admission",
            exact_f64(self.log.dropped_records()),
        ));
        self.metrics.record(&Metric::new(
            CONTROL_LOSS_METRIC,
            MetricKind::Counter,
            "critical events that reached the visible control_loss state",
            exact_f64(self.critical_path.control_loss_total()),
        ));
        self.metrics.record(&Metric::new(
            CONTROL_LOSS_HELD_METRIC,
            MetricKind::Gauge,
            "critical events held for replay on a returning channel",
            exact_f64(u64::try_from(self.critical_path.held_control_loss()).unwrap_or(u64::MAX)),
        ));
    }
}

/// Converts a bounded counter to a metric value.
///
/// The counters are drop/loss/held-record counts bounded well below 2^53, the
/// largest integer `f64` represents exactly, so the widening is lossless. The
/// cast is annotated rather than split arithmetically: an artificial
/// half-and-recombine would be less clear than a stated bound.
// Owner: this crate. Operation: metric value publication.
// Removal condition: never (the counters are structurally bounded).
#[allow(clippy::cast_precision_loss)]
fn exact_f64(value: u64) -> f64 {
    value as f64
}

/// Result of one install attempt.
#[derive(Clone, Debug)]
pub enum ObservabilityInstallOutcome {
    /// This call installed the stack.
    Installed(ObservabilityInstall),
    /// The stack was already installed; the first owner is unchanged and these
    /// are its live handles.
    AlreadyInstalled(ObservabilityInstall),
}

impl ObservabilityInstallOutcome {
    /// The live handles, whether installed now or previously.
    #[must_use]
    pub fn handles(&self) -> &ObservabilityInstall {
        match self {
            Self::Installed(install) | Self::AlreadyInstalled(install) => install,
        }
    }
}

static INSTALL: OnceLock<ObservabilityInstall> = OnceLock::new();

/// Owner of the rolling appender's writer thread for the process lifetime.
///
/// `RollingLogHandle` is not cloneable and its `Drop` requests shutdown, so the
/// handle is owned here — a `OnceLock` dropped only at process exit — rather
/// than by a local in `install`. The documented `shutdown` path stays the only
/// thing that stops the appender.
static APPENDER: OnceLock<RollingLogHandle> = OnceLock::new();

/// Installs the whole observability runtime, or returns the existing one.
///
/// Diagnostics never gate startup (A13.10): a rejected configuration returns a
/// typed error and leaves the process free to run, and the refusal is never
/// turned into a panic or a fabricated success.
///
/// # Errors
///
/// Returns [`ObservabilityConfigError`] when the configuration bounds or the
/// profile/sink rule are violated, or when the rolling appender, event spool,
/// or last-resort stage cannot be opened. A returned error is honest: no
/// partial stack is presented as complete.
pub fn install(
    config: &ObservabilityConfig,
) -> Result<ObservabilityInstallOutcome, ObservabilityConfigError> {
    if let Some(existing) = INSTALL.get() {
        return Ok(ObservabilityInstallOutcome::AlreadyInstalled(
            existing.clone(),
        ));
    }
    config.validate()?;
    // Bind before installing process-global logging so a configured exporter
    // failure cannot be mistaken for a successful observability install.
    let metrics_listener = config
        .metrics_listen
        .as_deref()
        .map(TcpListener::bind)
        .transpose()
        .map_err(|_| {
            ObservabilityConfigError::Inconsistent("OpenMetrics endpoint could not bind")
        })?;
    let log = RollingLogHandle::start(&config.rolling_log).map_err(|_| {
        ObservabilityConfigError::Inconsistent("rolling log appender could not be opened")
    })?;
    install_subscriber(log.writer());
    // The bridge is built only where both halves of the option hold: an endpoint
    // is configured and this build has the `otlp` feature. In a default build
    // `otlp_enabled()` is false, `OtlpBridge::new` would refuse with
    // `FeatureDisabled`, and no socket is opened - the disabled half of A2 is
    // untouched. A configured but unusable endpoint is an install-time
    // configuration error, not a silently inert bridge.
    let otlp_bridge = match config.otlp_endpoint.as_deref() {
        Some(endpoint) if otlp_enabled() => Some(OtlpBridge::new(endpoint).map_err(|error| {
            ObservabilityConfigError::Inconsistent(match error {
                OtlpBridgeError::EndpointNotParsable | OtlpBridgeError::SchemeNotSupported => {
                    "OTLP collector endpoint is not a usable http:// host, port, and path"
                }
                _ => "OTLP collector endpoint is not usable",
            })
        })?),
        _ => None,
    };
    let install = ObservabilityInstall {
        log: log.writer(),
        metrics: Arc::new(MetricsRegistry::default()),
        critical_path: CriticalPath::new(sinks_for(config, &log.writer())?),
        // Taken from the bridge that was actually built, so the reported
        // disposition and the live transport cannot disagree. A configured
        // endpoint that built no bridge reached this line only when the feature
        // is off, because an unusable endpoint is refused above.
        otlp: match (&otlp_bridge, &config.otlp_endpoint) {
            (Some(_), _) => OtlpDisposition::Enabled,
            (None, Some(_)) => OtlpDisposition::FeatureDisabled,
            (None, None) => OtlpDisposition::NotConfigured,
        },
        otlp_bridge,
        profile: config.profile,
    };
    // The bridge is live, so it exports now. The verdict is the collector's own
    // status line: a refusal is recorded through the subscriber that is already
    // installed, never turned into a reported success, and it never gates
    // startup (A13.10).
    if let Some(bridge) = &install.otlp_bridge {
        export_bridge_startup_record(bridge, config.profile);
    }
    if let Some(listener) = metrics_listener {
        start_openmetrics_server(listener, Arc::clone(&install.metrics)).map_err(|_| {
            ObservabilityConfigError::Inconsistent("OpenMetrics endpoint could not start")
        })?;
    }
    // The appender handle must outlive this function: dropping it sets the
    // shared shutdown flag, which would make every later `try_send` drop its
    // record. Keeping it here ties the writer thread to the process lifetime.
    let _ = APPENDER.set(log);
    let _ = INSTALL.set(install.clone());
    Ok(ObservabilityInstallOutcome::Installed(install))
}

/// Exports the stack's own startup record through a live OTLP bridge.
///
/// This is the production caller of [`OtlpBridge::export`]: a bundle binary that
/// is built with the `otlp` feature and configured with an endpoint emits
/// through the bridge here, while a default startup has no bridge and emits
/// nothing. I16.4 requires process start to be visible, and this record is that
/// visibility on the bridge surface.
///
/// The verdict is the collector's observed status, never an assumption. A
/// refusal is written to the same rolling log the rest of the stack uses, so
/// I16.11's "silent success is forbidden" holds: an unsent record never produces
/// a reported success. Startup is not gated on the collector (A13.10), so the
/// refusal is recorded rather than promoted to an install failure.
fn export_bridge_startup_record(bridge: &OtlpBridge, profile: RuntimeProfile) {
    let record = OtlpExport {
        event: OTLP_STARTUP_EVENT,
        labels: vec![
            ("target".to_owned(), OBSERVABILITY_TARGET.to_owned()),
            ("profile".to_owned(), profile.as_str().to_owned()),
        ],
    };
    match bridge.export(&record) {
        Ok(()) => {}
        Err(error) => {
            // The endpoint itself is not logged: a configured URL may carry
            // userinfo, and I15.4 keeps secret material out of logs. The typed
            // reason already names the exact refusal.
            tracing::error!(
                reason = %error,
                "otlp bridge export refused; the record was not accepted by the collector"
            );
        }
    }
}

/// Starts the optional scrape listener on a detached process-lifetime thread.
///
/// The configured address is the only source for the bind target. Each
/// accepted connection serves one request and closes; the listener remains
/// available for later scrapes.
fn start_openmetrics_server(
    listener: TcpListener,
    metrics: Arc<MetricsRegistry>,
) -> io::Result<()> {
    thread::Builder::new()
        .name("eliot-openmetrics".to_owned())
        .spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                let _ = serve_openmetrics_request(stream, &metrics);
            }
        })
        .map(|_| ())
}

/// Serves one bounded-registry scrape without accepting metric identity from
/// the HTTP request.
fn serve_openmetrics_request(mut stream: TcpStream, metrics: &MetricsRegistry) -> io::Result<()> {
    let request_line = read_request_line(&mut stream)?;
    let (status, body) = match request_line {
        RequestLine::Invalid => ("400 Bad Request", "invalid HTTP request\n".to_owned()),
        RequestLine::OtherMethod => ("405 Method Not Allowed", "method not allowed\n".to_owned()),
        RequestLine::OtherTarget => ("404 Not Found", "not found\n".to_owned()),
        RequestLine::GetMetrics if !read_request_headers(&mut stream)? => {
            ("400 Bad Request", "invalid HTTP headers\n".to_owned())
        }
        RequestLine::GetMetrics => match openmetrics_body(metrics) {
            Some(body) => ("200 OK", body),
            None => (
                "500 Internal Server Error",
                "metric family metadata is inconsistent\n".to_owned(),
            ),
        },
    };
    let content_type = if status == "200 OK" {
        "application/openmetrics-text; version=1.0.0; charset=utf-8"
    } else {
        "text/plain; charset=utf-8"
    };

    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body.as_bytes())
}

/// Produces one valid `OpenMetrics` document, rejecting inconsistent family
/// metadata and removing the duplicate HELP/TYPE lines emitted per series.
fn openmetrics_body(metrics: &MetricsRegistry) -> Option<String> {
    let mut families: BTreeMap<String, (Option<String>, Option<String>)> = BTreeMap::new();
    let mut body = String::new();

    for line in metrics.expose().lines() {
        let declaration = line
            .strip_prefix("# HELP ")
            .map(|rest| (true, rest))
            .or_else(|| line.strip_prefix("# TYPE ").map(|rest| (false, rest)));
        if let Some((is_help, rest)) = declaration {
            let (name, value) = rest.split_once(' ')?;
            let (help, kind) = families.entry(name.to_owned()).or_default();
            let current = if is_help { help } else { kind };
            match current {
                Some(existing) if existing.as_str() == value => continue,
                Some(_) => return None,
                None => *current = Some(value.to_owned()),
            }
        }
        body.push_str(line);
        body.push('\n');
    }
    body.push_str("# EOF\n");
    Some(body)
}

#[derive(Clone, Copy)]
enum RequestLine {
    Invalid,
    OtherMethod,
    OtherTarget,
    GetMetrics,
}

/// Reads only the request-line facts needed by this endpoint. The parser uses
/// fixed state and consumes arbitrarily long tokens without retaining them.
fn read_request_line(stream: &mut TcpStream) -> io::Result<RequestLine> {
    const METRICS_PATH: &[u8] = b"/metrics";
    const HTTP_10: &[u8] = b"HTTP/1.0";
    const HTTP_11: &[u8] = b"HTTP/1.1";

    #[derive(Clone, Copy)]
    enum Part {
        Method,
        Target,
        Version,
        LineFeed,
    }

    let mut part = Part::Method;
    let mut byte = [0_u8; 1];
    let (mut method_matches, mut method_len) = (true, 0_usize);
    let (mut path_matches, mut path_len, mut query_started) = (true, 0_usize, false);
    let mut version = [0_u8; HTTP_10.len()];
    let mut version_len = 0_usize;

    loop {
        stream.read_exact(&mut byte)?;
        let byte = byte[0];
        match part {
            Part::Method if byte == b' ' => part = Part::Target,
            Part::Method if byte == b'\r' || byte == b'\n' => {
                return Ok(RequestLine::Invalid);
            }
            Part::Method => {
                method_matches &= b"GET".get(method_len) == Some(&byte);
                method_len = method_len.saturating_add(1);
            }
            Part::Target if byte == b' ' => part = Part::Version,
            Part::Target if byte == b'\r' || byte == b'\n' => {
                return Ok(RequestLine::Invalid);
            }
            Part::Target => {
                if byte == b'?' {
                    query_started = true;
                } else if !query_started {
                    path_matches &= METRICS_PATH.get(path_len) == Some(&byte);
                    path_len = path_len.saturating_add(1);
                }
            }
            Part::Version if byte == b'\r' => part = Part::LineFeed,
            Part::Version if byte == b'\n' => return Ok(RequestLine::Invalid),
            Part::Version => {
                if let Some(slot) = version.get_mut(version_len) {
                    *slot = byte;
                }
                version_len = version_len.saturating_add(1);
            }
            Part::LineFeed if byte == b'\n' => {
                if method_len == 0
                    || path_len == 0
                    || version_len != version.len()
                    || (version.as_slice() != HTTP_10 && version.as_slice() != HTTP_11)
                {
                    return Ok(RequestLine::Invalid);
                }
                if !method_matches || method_len != b"GET".len() {
                    return Ok(RequestLine::OtherMethod);
                }
                if !path_matches || path_len != METRICS_PATH.len() {
                    return Ok(RequestLine::OtherTarget);
                }
                return Ok(RequestLine::GetMetrics);
            }
            Part::LineFeed => return Ok(RequestLine::Invalid),
        }
    }
}

/// Drains headers through the terminating blank line with constant memory.
fn read_request_headers(stream: &mut TcpStream) -> io::Result<bool> {
    let mut byte = [0_u8; 1];
    let mut line_has_bytes = false;
    let mut saw_carriage_return = false;
    loop {
        stream.read_exact(&mut byte)?;
        match (saw_carriage_return, byte[0]) {
            (true, b'\n') if !line_has_bytes => return Ok(true),
            (true, b'\n') => {
                line_has_bytes = false;
                saw_carriage_return = false;
            }
            (true, _) | (false, b'\n') => return Ok(false),
            (false, b'\r') => saw_carriage_return = true,
            (false, _) => line_has_bytes = true,
        }
    }
}

/// Builds the I16.11 sink group for the configured profile.
///
/// The normal stage is `normal_writer` — the same bounded appender the
/// `tracing` rolling layer writes to, so a critical record and an ordinary
/// operational record share one retention policy and one queue instead of two
/// independent sinks that could disagree about what was written.
fn sinks_for(
    config: &ObservabilityConfig,
    normal_writer: &RollingLogWriter,
) -> Result<CriticalEventSinks, ObservabilityConfigError> {
    let (spool, last_resort) = match (config.profile, config.spool.as_ref()) {
        (RuntimeProfile::SystemService, _) => (SpoolSinks::absent(), Some(EventLogReport)),
        (_, Some(policy)) => {
            let spool = EventSpool::open(policy.clone()).map_err(|_| {
                ObservabilityConfigError::Inconsistent("event spool could not be opened")
            })?;
            (SpoolSinks::new(spool), None)
        }
        (_, None) => {
            return Err(ObservabilityConfigError::Inconsistent(
                "user_mode and portable profiles require a protected event spool",
            ));
        }
    };
    let normal_writer = normal_writer.clone();
    Ok(CriticalEventSinks {
        normal: Some(CriticalEventSinksEntry::new(
            move |record| match serde_json::to_string(record) {
                Ok(line) if normal_writer.try_send(&line) => SinkStatus::Delivered,
                Ok(_) => SinkStatus::Unavailable(UnavailableReason::Saturated),
                Err(_) => SinkStatus::Unavailable(UnavailableReason::NotApplicable),
            },
        )),
        spool: Some(spool),
        last_resort,
    })
}

/// Installs the JSON `tracing` subscriber over stderr and the rolling appender.
///
/// A foreign pre-existing global subscriber is kept as-is: the first owner
/// stands and no second global install is attempted, so a process that already
/// installed diagnostics keeps them.
fn install_subscriber(writer: RollingLogWriter) {
    let stderr_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_ansi(false)
        .with_target(true)
        .with_writer(std::io::stderr);
    let rolling_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_ansi(false)
        .with_target(true)
        .with_writer(writer);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(stderr_layer)
        .with(rolling_layer)
        .try_init();
}
