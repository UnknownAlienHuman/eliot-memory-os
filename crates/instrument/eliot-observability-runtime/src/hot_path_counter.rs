//! Hot-path resource counters and the bounded hot-path sink (I12.14, issue
//! #1734).
//!
//! I12.14 requires every hot operation to carry a measured queue wait, service
//! time, allocation figure, lock contention figure, cache behaviour figure and
//! degradation rate. This module is the **explicitly scoped owned
//! implementation** the issue admits for the resource counters: it measures
//! what a boundary can honestly attribute to the work that boundary performed,
//! and it reports the extent of that attribution with every figure.
//!
//! # What the allocation counter is, and is not
//!
//! There is **no global allocator replacement here**, in this crate or anywhere
//! else in the production contour. A process-wide heap delta under concurrency
//! cannot be attributed to one request, so this crate never produces one: the
//! counter below counts allocation events *reported by the measured code
//! itself* inside a request scope that the caller opened at the real owning
//! boundary, through the bounded [`HotPathResourceScope`] the boundary already
//! holds. Its coverage is therefore [`HotPathAllocationCoverage::Partial`]
//! whenever the boundary did not wrap every allocation site on the path, and a
//! reader can see that from the figure rather than from a claim.
//!
//! Async work that outlives the thread the scope was entered on is exactly why
//! the scope is carried by the boundary's own state rather than by a
//! thread-local: a request that migrates across an executor's threads stays
//! inside the scope that admitted it, and a scope that a boundary did not carry
//! contributes no allocation figure at all rather than a partial one it cannot
//! defend.
//!
//! # What the sink is
//!
//! The sink is the crate's own existing non-blocking appender,
//! [`RollingLogWriter`], reached through the same [`crate::MetricsRegistry`]
//! path every other record in this crate uses. A refused sample is refused
//! visibly: [`HotPathRecordSink::missing_coverage`] counts it, so sink
//! backpressure and loss produce a bounded missing-coverage counter instead of
//! a silently thinner record. Nothing here opens a file, a socket or a thread
//! on the emitting path, formats a large payload, or holds an application lock
//! while it emits.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::metrics::{Metric, MetricError, MetricKind, OpenMetrics};

/// Metric name of the hot-path stage-record admission counter.
pub const HOT_PATH_STAGE_RECORDS_METRIC: &str = "eliot_hot_path_stage_records_total";

/// Metric name of the hot-path missing-coverage counter.
///
/// This is the bounded counter that absorbs sink backpressure and loss: a
/// refused stage record advances it, so a saturated sink is visible as reduced
/// coverage rather than as an absence.
pub const HOT_PATH_MISSING_COVERAGE_METRIC: &str = "eliot_hot_path_missing_coverage_total";

/// Stable outcome vocabulary of one hot-path stage-record admission.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HotPathRecordOutcome {
    /// The record reached the bounded sink.
    Admitted,
    /// The bounded sink refused the record, so coverage is now missing.
    SinkRefused,
    /// The collector is disabled, so the record was not collected.
    CollectionDisabled,
}

impl HotPathRecordOutcome {
    /// The wire outcome name carried in the `outcome` label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::SinkRefused => "sink_refused",
            Self::CollectionDisabled => "collection_disabled",
        }
    }

    /// Every outcome, in increasing severity.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Admitted, Self::SinkRefused, Self::CollectionDisabled]
    }
}

/// The bounded, non-blocking hot-path record sink.
///
/// The sink holds one already-serialized stage record line and hands it to the
/// crate's existing non-blocking appender. It never touches the filesystem, the
/// network, or an application lock on the emitting thread, and it spawns no
/// task per sample. A refused enqueue advances [`Self::missing_coverage`].
#[derive(Clone, Debug)]
pub struct HotPathRecordSink {
    writer: crate::rolling_log::RollingLogWriter,
    /// Stage records the sink carried.
    admitted: Arc<AtomicU64>,
    /// Stage records the bounded sink refused, plus records the collector
    /// disabled. This is the bounded missing-coverage counter.
    missing_coverage: Arc<AtomicU64>,
}

impl HotPathRecordSink {
    /// Builds a sink over the crate's existing rolling appender.
    #[must_use]
    pub fn new(writer: crate::rolling_log::RollingLogWriter) -> Self {
        Self {
            writer,
            admitted: Arc::new(AtomicU64::new(0)),
            missing_coverage: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Offers one already-serialized record to the bounded sink.
    ///
    /// Returns [`HotPathRecordOutcome::SinkRefused`] when the bounded queue is
    /// full or the writer thread has stopped. A refusal is a counted loss of
    /// coverage, never a successful write, and the caller continues: the sink
    /// never returns an error that a governed caller would have to handle on
    /// its result path.
    pub fn offer(&self, line: &str) -> HotPathRecordOutcome {
        if self.writer.try_send(line) {
            self.admitted.fetch_add(1, Ordering::Relaxed);
            HotPathRecordOutcome::Admitted
        } else {
            self.missing_coverage.fetch_add(1, Ordering::Relaxed);
            HotPathRecordOutcome::SinkRefused
        }
    }

    /// Stage records this sink carried.
    #[must_use]
    pub fn admitted_records(&self) -> u64 {
        self.admitted.load(Ordering::Relaxed)
    }

    /// Records the sink refused, the bounded missing-coverage counter.
    #[must_use]
    pub fn missing_coverage(&self) -> u64 {
        self.missing_coverage.load(Ordering::Relaxed)
    }

    /// Publishes the two sink counters on the shared bounded metric registry.
    ///
    /// The counters are published before a readback treats the sink as
    /// complete, so a scrape is never a coverage success indication while
    /// records are being lost. The `profile` label is the install's own
    /// installation profile, not a fixed value.
    pub fn publish_counters(
        &self,
        registry: &crate::bootstrap::MetricsRegistry,
        subject: &crate::metric_groups::MetricSubject,
    ) {
        for outcome in HotPathRecordOutcome::all() {
            let value = match outcome {
                HotPathRecordOutcome::Admitted => counter_value(self.admitted_records()),
                // A disabled collection and a refused sink are the same visible
                // condition to a readback: coverage this collector did not
                // produce. They stay separate outcomes so an operator can tell
                // them apart, and both report the same bounded counter so
                // neither is invisible.
                HotPathRecordOutcome::SinkRefused | HotPathRecordOutcome::CollectionDisabled => {
                    counter_value(self.missing_coverage())
                }
            };
            publish_counter(
                registry,
                HOT_PATH_STAGE_RECORDS_METRIC,
                "hot-path stage records by bounded-sink admission outcome",
                subject,
                outcome,
                value,
            );
        }
        publish_counter(
            registry,
            HOT_PATH_MISSING_COVERAGE_METRIC,
            "hot-path stage records the bounded sink refused, counted as missing coverage",
            subject,
            HotPathRecordOutcome::SinkRefused,
            counter_value(self.missing_coverage()),
        );
    }
}

/// Converts one bounded counter to its exposition value.
///
/// The `u32` narrowing is the same one the crate's other gauges already make
/// and the registry's [`MetricError::NonFiniteValue`] guard still refuses a
/// value the exporter cannot render. A counter above the narrowing's range is
/// reported at that range rather than silently wrapped, and a counter is a
/// monotone count, so a value at the ceiling is still an accurate report that
/// the collector is saturated.
fn counter_value(count: u64) -> f64 {
    f64::from(u32::try_from(count).unwrap_or(u32::MAX))
}

/// Records one bounded hot-path counter sample against the shared registry.
///
/// Every label is a closed value from the caller's already-validated subject:
/// the binary, module, work class, profile and route come from the catalogue's
/// own enumerations and from one fixed site identity, and the outcome is a
/// closed vocabulary. No request id, attempt id, task text, prompt, user text,
/// or error string reaches a label, so repeated unique content cannot open a
/// new series through this dimension.
fn publish_counter(
    registry: &crate::bootstrap::MetricsRegistry,
    name: &'static str,
    help: &'static str,
    subject: &crate::metric_groups::MetricSubject,
    outcome: HotPathRecordOutcome,
    value: f64,
) {
    let labels = [
        ("binary", subject.binary.as_str()),
        ("module", subject.module.as_str()),
        ("work_class", subject.work_class.as_str()),
        ("route_fingerprint_id", subject.route.as_str()),
        ("outcome", outcome.as_str()),
        ("profile", subject.profile.as_str()),
    ];
    let _ = registry
        .with_open_metrics(|open: &mut OpenMetrics| {
            open.record(&Metric::new(name, MetricKind::Counter, help, value).with_labels(&labels))
        })
        .ok_or(MetricError::InvalidLabel);
}

/// One allocation event the measured code reported inside a request scope.
///
/// A `HotPathAllocationEvent` is reported by the boundary that allocated, not
/// inferred from a heap delta. It therefore carries the bytes that allocation
/// actually asked for and nothing else, and a boundary that reports no event
/// reports no figure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HotPathAllocationEvent {
    /// Bytes this allocation requested.
    pub bytes: usize,
}

/// The resource counters one real boundary observed for one execution attempt.
///
/// The scope is carried by the boundary's own state, so it survives an async
/// hop. `allocations` is `None` when the boundary admitted no request scope,
/// which reads as `Unknown` upstream rather than as a measured zero.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HotPathResourceCounters {
    /// Allocation events the boundary's own request scope observed.
    allocations: Option<HotPathAllocationObservation>,
    /// Lock acquisitions the boundary made at the actual lock owner.
    lock_acquisitions: u64,
    /// Acquisitions that had to wait for the owner.
    lock_contended: u64,
    /// Nanoseconds the boundary waited for the owner, within one boot.
    lock_wait_nanos: u64,
    /// Cache lookups the boundary made at the actual lookup site.
    cache_lookups: u64,
    /// Lookups the cache answered.
    cache_hits: u64,
    /// Lookups the cache did not hold.
    cache_misses: u64,
    /// Lookups answered from a superseded revision.
    cache_stale: u64,
    /// Lookups that deliberately skipped the cache.
    cache_bypasses: u64,
}

/// The allocation figure one request scope observed, with the coverage that
/// scope actually had.
///
/// The coverage is a property of the scope, not of the reading: a scope that
/// covered every allocation site on the path reports `Complete`; one that
/// covered only the sites that reported through it reports `Partial`, and the
/// figure is still reported with that extent rather than being widened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HotPathAllocationObservation {
    /// Allocation events the scope observed.
    pub allocation_count: u64,
    /// Bytes the scope observed.
    pub allocated_bytes: u64,
    /// Whether the scope covered every allocation site on the measured path.
    pub coverage: HotPathAllocationCoverage,
}

/// Whether an observed allocation scope covered its whole measured path.
///
/// `Partial` means the remainder of the path's allocations is unobserved, which
/// is not zero.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HotPathAllocationCoverage {
    /// Every allocation site on the measured path reported through the scope.
    Complete,
    /// Only the reporting allocation sites on the measured path were observed.
    Partial,
}

impl HotPathResourceCounters {
    /// Records one allocation event the boundary's own scope observed.
    ///
    /// A boundary that admitted no request scope reports the event nowhere: a
    /// scope is the attribution, and without one there is no honest figure.
    pub fn record_allocation(&mut self, event: HotPathAllocationEvent, scope_covered: bool) {
        let coverage = if scope_covered {
            HotPathAllocationCoverage::Complete
        } else {
            HotPathAllocationCoverage::Partial
        };
        let observation = self
            .allocations
            .get_or_insert(HotPathAllocationObservation {
                allocation_count: 0,
                allocated_bytes: 0,
                coverage,
            });
        observation.allocation_count = observation.allocation_count.saturating_add(1);
        observation.allocated_bytes = observation
            .allocated_bytes
            .saturating_add(u64::try_from(event.bytes).unwrap_or(u64::MAX));
    }

    /// Records one lock acquisition at the actual lock owner, with the time the
    /// acquisition waited before the owner released it.
    pub fn record_lock_acquisition(&mut self, waited_nanos: Option<u64>) {
        self.lock_acquisitions = self.lock_acquisitions.saturating_add(1);
        match waited_nanos {
            None => {}
            Some(nanos) => {
                self.lock_contended = self.lock_contended.saturating_add(1);
                self.lock_wait_nanos = self.lock_wait_nanos.saturating_add(nanos);
            }
        }
    }

    /// Records one cache lookup outcome at the actual lookup site.
    pub fn record_cache_lookup(&mut self, outcome: HotPathCacheOutcome) {
        self.cache_lookups = self.cache_lookups.saturating_add(1);
        match outcome {
            HotPathCacheOutcome::Hit => self.cache_hits = self.cache_hits.saturating_add(1),
            HotPathCacheOutcome::Miss => self.cache_misses = self.cache_misses.saturating_add(1),
            HotPathCacheOutcome::Stale => self.cache_stale = self.cache_stale.saturating_add(1),
            HotPathCacheOutcome::Bypass => {
                self.cache_bypasses = self.cache_bypasses.saturating_add(1);
            }
        }
    }

    /// The allocation figure this boundary observed, with the scope that
    /// attributed it.
    #[must_use]
    pub fn allocations(&self) -> Option<HotPathAllocationObservation> {
        self.allocations
    }
}

/// One cache lookup outcome observed at an actual lookup site.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HotPathCacheOutcome {
    /// The cache answered the lookup.
    Hit,
    /// The cache did not hold the answer.
    Miss,
    /// The cache answered from a superseded revision.
    Stale,
    /// The lookup deliberately skipped the cache.
    Bypass,
}

/// The one declared monotonic clock domain the hot path is differenced within.
///
/// The domain identity is a fixed site identity, not a process-local
/// timestamp: two readings of this domain are comparable, and a reading of any
/// other source is never mixed into it. [`std::time::Instant`] is monotonic
/// within one boot, and a boot change invalidates every reading taken before
/// it, which is why the boot identity travels with the record rather than with
/// the reading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HotPathMonotonicClock {
    /// Exact identity of the monotonic source within the boot.
    pub domain_id: &'static str,
}

impl HotPathMonotonicClock {
    /// Binds one monotonic source to its declared domain identity.
    #[must_use]
    pub const fn new(domain_id: &'static str) -> Self {
        Self { domain_id }
    }

    /// Reads the current instant within this domain.
    #[must_use]
    pub fn now(&self) -> Instant {
        Instant::now()
    }

    /// The elapsed milliseconds between two readings of this same domain.
    ///
    /// Both readings must be from this clock; a reading from any other source
    /// is not comparable, which is why the boundary passes its own readings
    /// rather than a process-local timestamp. An interval longer than the
    /// `u64` millisecond range saturates at that range instead of wrapping.
    #[must_use]
    pub fn elapsed_ms(&self, from: Instant, to: Instant) -> u64 {
        u64::try_from(to.saturating_duration_since(from).as_millis()).unwrap_or(u64::MAX)
    }
}

/// A named wait one boundary observed inside its own service interval.
///
/// A wait inside service is preserved as its own named component rather than
/// subtracted from the service total, so the accounting rule is additive and a
/// reader can see how much of service was spent waiting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HotPathObservedWait {
    /// Exact declared name of the waited-on condition.
    pub component: String,
    /// Time the service interval spent in this component.
    pub waited_ms: u64,
}

/// How the hot-path collector is running.
///
/// `Disabled` is a declared mode, not a failure: a disabled collector reports
/// nothing, changes no governed result, and its own cost is zero.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HotPathCollectionState {
    /// Collection is off; the governed result is unaffected.
    Disabled,
    /// A declared fraction of attempts is sampled.
    Sampled,
    /// Every attempt is collected.
    Full,
}

impl HotPathCollectionState {
    /// The wire state name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Sampled => "sampled",
            Self::Full => "full",
        }
    }
}

/// The declared clock domain the Kernel and daemon hot paths are differenced
/// within.
///
/// Both processes read `std::time::Instant`, which is monotonic within one
/// boot; a boot change invalidates every reading taken before it, which is why
/// the boot identity travels with the record rather than the reading.
pub const HOT_PATH_MONOTONIC_DOMAIN: &str = "std::time::Instant";

/// The one declared clock domain both composition roots bind.
#[must_use]
pub fn hot_path_clock() -> HotPathMonotonicClock {
    HotPathMonotonicClock::new(HOT_PATH_MONOTONIC_DOMAIN)
}
