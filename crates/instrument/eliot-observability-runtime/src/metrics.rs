//! Bounded-label `OpenMetrics` exposition (I16.1 metrics, I16.2 exporter).
//!
//! I16.1 makes metrics a distinct surface from logs and audit: aggregated
//! performance/health/cost with bounded labels. [`OpenMetrics`] therefore
//! accepts only a fixed label key set, a per-series label count, a label
//! value length, and a total series cardinality. A rejected sample is
//! rejected, never silently folded into an existing series and never emitted
//! with unbounded cardinality.
//!
//! I16.9 requires bounded local retention, so the registry is a bounded
//! counter/gauge/unhistogram store: once `max_series` distinct series are
//! present, further new series are refused and the refusal is visible through
//! [`OpenMetrics::rejected_series`].

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::config::{MAX_METRIC_LABEL_CHARS, MAX_METRIC_LABELS, MAX_METRIC_SERIES};

/// Aggregation semantics of one exported series (I16.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricKind {
    /// Monotone total.
    Counter,
    /// Current value, rising or falling.
    Gauge,
    /// Count plus sum of observed values.
    Summary,
}

/// Typed metric rejection. Every variant keeps the sample's identity out of
/// the error value so a rejection is never itself a disclosure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MetricError {
    /// The metric name is blank or outside the exporter charset.
    #[error("metric name is not exportable")]
    InvalidName,
    /// The value is not finite, so no exposition is possible.
    #[error("metric value must be finite")]
    NonFiniteValue,
    /// More labels than `MAX_METRIC_LABELS` were supplied.
    #[error("metric label count exceeds the bounded limit")]
    TooManyLabels,
    /// A label key or value is blank, oversized, or outside the charset.
    #[error("metric label is not exportable")]
    InvalidLabel,
    /// The bounded series registry is full.
    #[error("metric series registry is full")]
    RegistryFull,
}

#[derive(Clone, Debug)]
struct Series {
    name: String,
    kind: MetricKind,
    help: String,
    labels: Vec<(String, String)>,
    value: f64,
    count: u64,
}

/// Bounded `OpenMetrics` registry and text exposition.
#[derive(Clone, Debug, Default)]
pub struct OpenMetrics {
    series: BTreeMap<String, Series>,
    rejected_series: u64,
}

impl OpenMetrics {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one sample.
    ///
    /// A `Counter` accumulates; a `Gauge` replaces; a `Summary` accumulates a
    /// count and a sum, which the exposition renders as
    /// `metric_sum`/`metric_count`.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the name, value, or labels are not
    /// exportable, or [`MetricError::RegistryFull`] when a new series would
    /// exceed the bounded cardinality.
    pub fn record(&mut self, metric: &Metric<'_>) -> Result<(), MetricError> {
        let name = metric.name;
        if !is_exportable_name(name) {
            return Err(MetricError::InvalidName);
        }
        if !metric.value.is_finite() {
            return Err(MetricError::NonFiniteValue);
        }
        if metric.labels.len() > MAX_METRIC_LABELS {
            return Err(MetricError::TooManyLabels);
        }
        let mut labels: Vec<(String, String)> = Vec::with_capacity(metric.labels.len());
        for (key, value) in metric.labels {
            if !is_exportable_label(key) || !is_exportable_label(value) {
                return Err(MetricError::InvalidLabel);
            }
            labels.push(((*key).to_owned(), (*value).to_owned()));
        }
        labels.sort_unstable();
        let identity = series_identity(name, &labels);
        if let Some(series) = self.series.get_mut(&identity) {
            match metric.kind {
                MetricKind::Counter | MetricKind::Summary => {
                    series.value += metric.value;
                    series.count = series.count.saturating_add(1);
                }
                MetricKind::Gauge => {
                    series.value = metric.value;
                    series.count = series.count.saturating_add(1);
                }
            }
            return Ok(());
        }
        if self.series.len() >= MAX_METRIC_SERIES {
            self.rejected_series = self.rejected_series.saturating_add(1);
            return Err(MetricError::RegistryFull);
        }
        self.rejected_series = self.rejected_series.saturating_add(1);
        self.series.insert(
            identity,
            Series {
                name: name.to_owned(),
                kind: metric.kind,
                help: metric.help.to_owned(),
                labels,
                value: metric.value,
                count: 1,
            },
        );
        Ok(())
    }

    /// Increments a counter with no labels.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] under the same rules as
    /// [`OpenMetrics::record`].
    pub fn increment(&mut self, name: &str, help: &str, delta: f64) -> Result<(), MetricError> {
        self.record(&Metric::new(name, MetricKind::Counter, help, delta))
    }

    /// Series refused because the bounded registry was full.
    #[must_use]
    pub fn rejected_series(&self) -> u64 {
        self.rejected_series
    }

    /// Distinct series currently retained.
    #[must_use]
    pub fn series_count(&self) -> usize {
        self.series.len()
    }

    /// Renders the `OpenMetrics` text exposition.
    ///
    /// Deterministic: series are ordered by identity, so a scrape is
    /// byte-stable for the same recorded state.
    #[must_use]
    pub fn expose(&self) -> String {
        let mut out = String::new();
        for series in self.series.values() {
            let _ = writeln!(out, "# HELP {} {}", series.name, escape_help(&series.help));
            let _ = writeln!(out, "# TYPE {} {}", series.name, series.kind.as_str());
            match series.kind {
                MetricKind::Summary => {
                    let _ = writeln!(
                        out,
                        "{}_sum{} {}",
                        series.name,
                        render_labels(&series.labels),
                        format_value(series.value)
                    );
                    let _ = writeln!(
                        out,
                        "{}_count{} {}",
                        series.name,
                        render_labels(&series.labels),
                        series.count
                    );
                }
                MetricKind::Counter | MetricKind::Gauge => {
                    let _ = writeln!(
                        out,
                        "{}{} {}",
                        series.name,
                        render_labels(&series.labels),
                        format_value(series.value)
                    );
                }
            }
        }
        out
    }
}

impl MetricKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Summary => "summary",
        }
    }
}

/// One bounded metric sample.
#[derive(Clone, Copy, Debug)]
pub struct Metric<'a> {
    name: &'a str,
    kind: MetricKind,
    help: &'a str,
    value: f64,
    labels: &'a [(&'a str, &'a str)],
}

impl<'a> Metric<'a> {
    /// Builds one sample. `labels` must already be a bounded, low-cardinality
    /// set: the exporter validates the count, charset, and length, and refuses
    /// anything else.
    #[must_use]
    pub const fn new(name: &'a str, kind: MetricKind, help: &'a str, value: f64) -> Self {
        Self {
            name,
            kind,
            help,
            value,
            labels: &[],
        }
    }

    /// Returns the sample with `labels` attached.
    #[must_use]
    pub const fn with_labels(mut self, labels: &'a [(&'a str, &'a str)]) -> Self {
        self.labels = labels;
        self
    }
}

fn is_exportable_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn is_exportable_label(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_METRIC_LABEL_CHARS
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte == b'.'
        })
}

fn series_identity(name: &str, labels: &[(String, String)]) -> String {
    let mut identity = String::from(name);
    for (key, value) in labels {
        let _ = write!(identity, "|{key}={value}");
    }
    identity
}

fn render_labels(labels: &[(String, String)]) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let rendered = labels
        .iter()
        .map(|(key, value)| format!("{key}=\"{value}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{rendered}}}")
}

fn escape_help(help: &str) -> String {
    help.replace('\\', "\\\\").replace('\n', "\\n")
}

fn format_value(value: f64) -> String {
    if value.fract() == 0.0 && value.is_finite() {
        format!("{value:.1}")
    } else {
        value.to_string()
    }
}
