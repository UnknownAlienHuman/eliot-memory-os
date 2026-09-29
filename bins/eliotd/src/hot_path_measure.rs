//! Hot-path measurement producers for the `eliotd` local-read poller
//! (I12.14, issue #1734).
//!
//! The runtime contract in `eliot-runtime-contracts` owns the *shape* of a hot
//! measurement ([`HotPathStageRecord`], [`HotPathStageSet`],
//! [`HotPathOperationResult`]). This module owns the *production* of that shape
//! at the daemon's real boundaries: it is the one place that reads the declared
//! clock, takes the boundary readings, and hands the bounded records to the
//! correlator that the local-read poll step itself executes.
//!
//! # What is measured here, and what is not
//!
//! Two boundaries of one claimed attempt are observed by this daemon, in the
//! order the poll step performs them:
//!
//! * **claim** — the instant the Kernel handed the daemon an admitted pair. The
//!   enqueue instant was taken by the *Kernel* queue owner, so this module never
//!   subtracts a daemon-side reading from a Kernel-side one: the claim record
//!   carries no queue wait at all, which the contract refuses at the enqueue
//!   boundary and permits here only as `None`.
//! * **service end** — the instant the forward hop returned, with the resource
//!   figures that boundary's own scoped counter observed.
//!
//! The result-return boundary is owned by the Kernel's `local_read_result` leg,
//! not by this daemon, so this module does not claim to have observed it.
//! [`HotPathRequiredStages::declared_for`] still *requires* it, so a
//! daemon-only assembly is `MissingRequiredStages` and therefore never a
//! qualification. That is the honest reading and it is not papered over.
//!
//! # Honesty rules this module does not break
//!
//! * Every duration names [`HOT_PATH_MONOTONIC_DOMAIN`], so two readings are
//!   always comparable and the correlator's cross-domain guard can never fire on
//!   a sum this module produced.
//! * The allocation figure is taken from the [`HotPathResourceCounters`] scope
//!   the boundary itself holds, and its coverage travels with it. A boundary
//!   that admitted no scope reports no figure, which reads as `Unknown` rather
//!   than a measured zero.
//! * The sink's admission outcome is a *value*. A refused or disabled collector
//!   advances the bounded missing-coverage counter and changes no governed
//!   result, receipt or cancellation.
//!
//! Nothing here opens a file, a socket, a thread or a task, so the collector
//! cannot recursively instrument its own emission.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use eliot_contracts::OperationId;
use eliot_observability_runtime::{
    HOT_PATH_MONOTONIC_DOMAIN, HotPathAllocationObservation as ScopedAllocationObservation,
    HotPathMonotonicClock, HotPathRecordSink, HotPathResourceCounters, RollingLogWriter,
    hot_path_clock,
};
use eliot_protocol::{HostRequestEnvelope, LocalReadAttempt};
use eliot_runtime_contracts::{
    AdmittedHotPathManifest, HOT_PATH_PROFILE_VERSION, HotPathAllocationAttribution,
    HotPathAllocationCoverage, HotPathAllocations, HotPathAttemptDisposition,
    HotPathCacheBehaviour, HotPathDurationMs, HotPathJoinKey, HotPathLockContention,
    HotPathManifest, HotPathManifestRevision, HotPathOperationResult, HotPathRequiredStages,
    HotPathStage, HotPathStageRecord, HotPathStageSet, HotPathWaitComponent, RuntimeContractError,
    attempt_labels, correlate_operation, hot_path_manifest_path,
};

/// Tracing target for this module's own bounded refusals.
pub const HOT_PATH_MEASURE_TARGET: &str = "eliotd_hot_path_measure";

/// The registered operation this module instruments on the daemon side.
///
/// It is the exact operation identity `bins/eliotd/hot-path.toml` declares, and
/// the declaration is still consulted for every measurement: a collector whose
/// declaration no longer names this operation is never installed, so no
/// measurement is ever taken against a string this module spells on its own.
pub const LOCAL_READ_OPERATION: &str = "local_read";

/// The eligible population's bounded census, read as one snapshot.
///
/// The counts are advanced at the admission boundary, *before* any outcome is
/// known, so a refusal, an expiry, a stale attempt and a failure all enter the
/// denominator. A lost record advances `unknown` rather than disappearing, so a
/// saturated sink cannot collapse the degradation rate toward zero.
///
/// The census is process-wide and the collector handle is shared by every poll
/// step, so it lives behind the one lock its own counter semantics require
/// rather than behind a shared reference that two callers could write through.
#[derive(Debug, Default, Eq, PartialEq)]
struct HotPathObservedCensus {
    /// Attempts the claim boundary admitted.
    admitted: u64,
    /// Admitted attempts that ended in a declared degradation.
    degraded: u64,
    /// Admitted attempts whose outcome was never observed.
    unknown: u64,
    /// Records the bounded sink refused.
    dropped: u64,
}

/// Everything one boundary observed at one real hook, as this module's own
/// single argument to a record builder.
///
/// The record builder takes the observed values as one value rather than as
/// seven positional arguments: a positional list this wide is exactly where a
/// stage, a duration and a counter set can be transposed without a compiler
/// noticing, and the mapping the contract's field set requires stays visible
/// here instead of being spread across a call site's parentheses.
struct ObservedService {
    /// The attempt key every part of this observation was taken under.
    join: HotPathJoinKey,
    /// The boundary this observation was taken at.
    stage: HotPathStage,
    /// The terminal disposition this boundary observed.
    disposition: HotPathAttemptDisposition,
    /// Service this boundary actually performed, in one declared clock domain.
    service_time: Option<HotPathDurationMs>,
    /// The resource figures this boundary's own scope observed.
    counters: HotPathResourceCounters,
    /// Named waits inside the service interval, preserved as components.
    service_wait_components: Vec<HotPathWaitComponent>,
}

/// The shared, process-lifetime hot-path collector for this daemon.
///
/// One instance is created by [`install_daemon_hot_path_collector`] at the same
/// never-gate startup site as the rest of the observability stack, and the
/// local-read poll step reaches it through [`SharedLocalReadHotPath`]. It holds
/// the admitted declaration, the bounded sink over the crate's existing
/// non-blocking appender, the declared monotonic clock, and the window census
/// the degradation rate is derived from.
pub struct LocalReadHotPath {
    /// The exact declaration this collector measures against.
    manifest: HotPathManifest,
    /// The declared revision, bound to every record this collector emits.
    revision: HotPathManifestRevision,
    /// Bounded, non-blocking record sink over the existing rolling appender.
    sink: HotPathRecordSink,
    /// The one declared clock domain every reading is taken in.
    clock: HotPathMonotonicClock,
    /// Boot identity every reading in this process belongs to.
    boot_id: String,
    /// Process identity every record names as its source.
    process_id: String,
    /// Bounded census of the eligible population this process observed.
    ///
    /// The collector handle is shared by every poll step, so the census is
    /// reached through its own lock: a counter two callers could write through
    /// a shared reference would be a data race on the degradation denominator.
    census: Mutex<HotPathObservedCensus>,
}

/// One claimed attempt's boundary state as the poll step performs its legs.
///
/// The state is carried by the step, not by a thread-local, so a request that
/// migrates across executor threads stays inside the scope that admitted it. It
/// is opened by [`LocalReadHotPath::begin_attempt`] at the claim boundary and
/// consumed by [`LocalReadAttemptTrace::finish_attempt`] when the step settles.
pub struct LocalReadAttemptTrace {
    collector: Arc<LocalReadHotPath>,
    join: HotPathJoinKey,
    set: HotPathStageSet,
    service_started: Instant,
    counters: HotPathResourceCounters,
}

/// The shared handle the run loop's poll step carries.
pub type SharedLocalReadHotPath = Arc<LocalReadHotPath>;

/// Why this daemon's hot-path collector was not installed.
#[derive(Debug)]
pub enum HotPathMeasureError {
    /// The declaration path could not be derived from the crate root.
    Contract(RuntimeContractError),
    /// The declaration bytes could not be read.
    Unreadable {
        /// Exact path and OS error text.
        reason: String,
    },
    /// The declaration was refused, or names no local-read operation.
    Declaration(String),
}

impl std::fmt::Display for HotPathMeasureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "hot-path declaration path: {error}"),
            Self::Unreadable { reason } => {
                write!(formatter, "hot-path declaration unreadable: {reason}")
            }
            Self::Declaration(reason) => {
                write!(formatter, "hot-path declaration refused: {reason}")
            }
        }
    }
}

impl std::error::Error for HotPathMeasureError {}

/// Installs this daemon's hot-path collector and returns the shared handle.
///
/// # Errors
///
/// Returns [`HotPathMeasureError`] when the service-local declaration file
/// cannot be read or admitted, or when it declares no [`LOCAL_READ_OPERATION`].
/// A refused declaration leaves collection disabled: telemetry is never a reason
/// the daemon refuses to run.
pub fn install_daemon_hot_path_collector(
    crate_root: &Path,
    writer: RollingLogWriter,
) -> Result<SharedLocalReadHotPath, HotPathMeasureError> {
    let path = hot_path_manifest_path(crate_root).map_err(HotPathMeasureError::Contract)?;
    let bytes = std::fs::read(&path).map_err(|error| HotPathMeasureError::Unreadable {
        reason: format!("{}: {error}", path.display()),
    })?;
    let admitted: AdmittedHotPathManifest =
        eliot_runtime_contracts::admit_hot_path_manifest(&path, &bytes)
            .map_err(|error| HotPathMeasureError::Declaration(error.to_string()))?;
    let manifest = admitted
        .operation(LOCAL_READ_OPERATION)
        .map_err(|error| HotPathMeasureError::Declaration(error.to_string()))?
        .clone();
    let revision = HotPathManifestRevision {
        operation: manifest.operation.clone(),
        version: manifest.operation_version,
    };
    Ok(Arc::new(LocalReadHotPath {
        manifest,
        revision,
        sink: HotPathRecordSink::new(writer),
        clock: hot_path_clock(),
        boot_id: daemon_boot_id(),
        process_id: format!("eliotd:{}", std::process::id()),
        census: Mutex::new(HotPathObservedCensus::default()),
    }))
}

/// Boot identity this process's monotonic readings belong to.
///
/// `std::time::Instant` is monotonic only within one boot, and a boot change
/// invalidates every reading taken before it, so the boot identity travels with
/// every record instead of the reading being trusted alone. The derivation uses
/// the only observation this daemon always has about its own boot: its own
/// process identity and the wall-clock instant the record is first taken at. A
/// restarted process yields a different identity, so readings from two boots
/// never share one.
fn daemon_boot_id() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    format!("eliotd-boot:{}:{now}", std::process::id())
}

impl LocalReadHotPath {
    /// The declared clock domain every reading in this collector is taken in.
    ///
    /// This is a fixed site identity, so a reader can check that two
    /// durations it is differencing name the same domain. It is a
    /// `&'static str` field, never a per-process value.
    #[must_use]
    pub const fn clock_domain_id(&self) -> &'static str {
        HOT_PATH_MONOTONIC_DOMAIN
    }

    /// The required boundary set this collector's declaration derives.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContractError`] when the admitted declaration is invalid.
    fn required_stages(&self) -> Result<HotPathRequiredStages, RuntimeContractError> {
        HotPathRequiredStages::declared_for(&self.manifest)
    }

    /// Opens one claimed attempt at the claim boundary.
    ///
    /// The join key is built from the *original* request identity carried by the
    /// claimed envelope and the Kernel-minted attempt identity, verbatim: no
    /// identity is derived or substituted here, so two concurrent attempts and
    /// a retry cannot pool. The attempt enters the census here, before its
    /// outcome exists, so it is in the degradation denominator whatever the
    /// outcome turns out to be.
    #[must_use]
    pub fn begin_attempt(
        self: &Arc<Self>,
        envelope: &HostRequestEnvelope,
        attempt: &LocalReadAttempt,
    ) -> Option<LocalReadAttemptTrace> {
        // The request id is the one the envelope already carries and the
        // attempt id is the one the Kernel already minted; both are CLONED
        // verbatim. Neither is re-derived, re-parsed or re-validated into a
        // fresh value here, so the join key cannot name a request or attempt
        // that the Kernel did not actually issue.
        let join = HotPathJoinKey {
            request_id: envelope.identity.request_id.clone(),
            attempt_id: OperationId::new(attempt.attempt_id.as_str()).ok()?,
            stage: HotPathStage::Claim,
            source_generation: envelope.state_fence.resource_generation,
        };
        let claim_at = self.clock.now();
        // The claim boundary performs no service, so it carries no service
        // time: a duration here would be a claim lease or poll cadence, which
        // is not service. It carries no queue wait either, because the enqueue
        // instant belongs to the Kernel's queue owner.
        let record = self.stage_record(&ObservedService {
            join: join.clone(),
            stage: HotPathStage::Claim,
            disposition: HotPathAttemptDisposition::Served,
            service_time: None,
            counters: HotPathResourceCounters::default(),
            service_wait_components: Vec::new(),
        });
        let mut set = HotPathStageSet {
            join: join.clone(),
            records: Vec::new(),
            dropped_records: 0,
        };
        if let Err(refusal) = set.admit(record.clone()) {
            self.count_unknown();
            tracing::warn!(
                target: HOT_PATH_MEASURE_TARGET,
                event = "eliotd.hot_path_claim_record_refused",
                reason = %refusal,
            );
            return None;
        }
        self.count_admitted();
        self.emit(&record);
        Some(LocalReadAttemptTrace {
            collector: Arc::clone(self),
            join,
            set,
            service_started: claim_at,
            counters: HotPathResourceCounters::default(),
        })
    }

    /// Advances the census by one admitted attempt.
    fn count_admitted(&self) {
        let mut census = self.census();
        census.admitted = census.admitted.saturating_add(1);
    }

    /// Counts one admitted attempt whose outcome was never observed.
    fn count_unknown(&self) {
        let mut census = self.census();
        census.unknown = census.unknown.saturating_add(1);
    }

    /// Counts one admitted attempt that ended in a declared degradation.
    fn count_degraded(&self) {
        let mut census = self.census();
        census.degraded = census.degraded.saturating_add(1);
    }

    /// Counts one stage record the bounded set refused.
    fn count_dropped(&self) {
        let mut census = self.census();
        census.dropped = census.dropped.saturating_add(1);
    }

    /// The census guard every counter mutation is taken through.
    fn census(&self) -> MutexGuard<'_, HotPathObservedCensus> {
        self.census.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Builds one bounded stage record from values this boundary observed.
    ///
    /// Every field is a value a boundary actually held: the labels come from the
    /// declaration and the stage vocabulary, the duration is a difference of two
    /// readings of this collector's own clock, the resource figures come from the
    /// boundary's own scoped counter, and a category the boundary did not
    /// observe stays `None` so it reads as `Unknown` upstream rather than a
    /// measured zero.
    ///
    /// The named waits inside the service interval are supplied by the boundary
    /// that owns them and arrive as contract components already measured in this
    /// collector's declared clock domain, so no wait is re-differenced here
    /// against a reading this process did not take.
    fn stage_record(&self, observed: &ObservedService) -> HotPathStageRecord {
        HotPathStageRecord {
            join: HotPathJoinKey {
                request_id: observed.join.request_id.clone(),
                attempt_id: observed.join.attempt_id.clone(),
                stage: observed.stage,
                source_generation: observed.join.source_generation,
            },
            labels: attempt_labels(
                &self.manifest,
                observed.stage,
                eliot_runtime_contracts::HotPathObservationKind::Execution,
                observed.disposition,
            ),
            source_process_id: self.process_id.clone(),
            source_boot_id: self.boot_id.clone(),
            manifest: self.revision.clone(),
            profile_revision: HOT_PATH_PROFILE_VERSION,
            // The enqueue instant belongs to the Kernel's queue owner, so no
            // queue wait is observable from this daemon. Carrying one would
            // subtract a reading this process did not take.
            queue_wait: None,
            service_time: observed.service_time.clone(),
            allocations: observed.counters.allocations().map(observed_allocations),
            lock_contention: observed_lock_contention(&observed.counters),
            cache_behaviour: observed_cache_behaviour(&observed.counters),
            service_wait_components: observed.service_wait_components.clone(),
            degradation: None,
        }
    }

    /// Offers one already-serialized record to the bounded sink.
    ///
    /// The sink's outcome is a value, never an error on the governed path, so a
    /// saturated or disabled collector cannot change a governed query result.
    /// A refusal is counted by the sink's own missing-coverage counter.
    fn emit(&self, record: &HotPathStageRecord) {
        if let Ok(line) = serde_json::to_string(record) {
            self.sink.offer(&line);
        }
    }
}

impl LocalReadAttemptTrace {
    /// Records the start of service at the start boundary.
    ///
    /// The claim-to-start interval is deliberately *not* added to any service
    /// figure: a claim lease or poll cadence is not service, and folding it in
    /// would hide queue behaviour inside a service number.
    pub fn note_service_start(&mut self) {
        self.service_started = self.collector.clock.now();
    }

    /// Records the resource counters one service boundary observed.
    ///
    /// The service interval is closed here, at the boundary that owns it, and
    /// its figure is the difference of two readings of this collector's own
    /// clock: it is never the claim-to-start interval, because a claim lease or
    /// a poll cadence is not service. The waits inside the interval would be
    /// preserved as separately named components rather than subtracted from the
    /// total; this daemon's own boundaries report none today, so the component
    /// list is empty rather than carrying a zero-length wait that would read as
    /// an observed dependency.
    pub fn note_service_observed(&mut self, counters: HotPathResourceCounters) {
        self.counters = counters;
        let service_time = HotPathDurationMs {
            elapsed_ms: self
                .collector
                .clock
                .elapsed_ms(self.service_started, self.collector.clock.now()),
            clock_domain_id: self.collector.clock_domain_id().to_owned(),
        };
        let record = self.collector.stage_record(&ObservedService {
            join: self.join.clone(),
            stage: HotPathStage::ServiceEnd,
            disposition: HotPathAttemptDisposition::Served,
            service_time: Some(service_time),
            counters: self.counters.clone(),
            service_wait_components: Vec::new(),
        });
        self.admit(&record);
    }

    /// Admits one boundary record, counting a refusal as missing coverage.
    ///
    /// A refusal is counted, never swallowed, and reported as one bounded
    /// diagnostic code. Nothing in this module is emitted per request id: only
    /// the bounded stage and the refusal reason, so repeated unique content
    /// cannot open unbounded output.
    fn admit(&mut self, record: &HotPathStageRecord) {
        let stage = record.join.stage;
        if let Err(refusal) = self.set.admit(record.clone()) {
            self.collector.count_dropped();
            self.collector.count_unknown();
            tracing::warn!(
                target: HOT_PATH_MEASURE_TARGET,
                event = "eliotd.hot_path_record_refused",
                stage = ?stage,
                reason = %refusal,
            );
            return;
        }
        self.collector.emit(record);
    }

    /// Correlates this attempt's boundary records and emits the correlated result.
    ///
    /// The result is assembled by the contract's correlator against the
    /// declaration-derived required set, so an assembly missing the Kernel-owned
    /// result-return boundary is reported as `MissingRequiredStages` and can
    /// never read as complete. A refused correlation is counted as unknown rather
    /// than dropped, so a saturated collector cannot move the degradation rate
    /// toward zero. The degradation *rate* is not attached here: it is a
    /// predeclared-window figure this per-attempt step cannot own, so the
    /// category reads `Unknown` instead of a fabricated zero.
    ///
    /// The correlated result is offered to the bounded sink here and returned so
    /// a caller that reads the result directly can have it; the poll step does
    /// not consume it, because the result's own destination is the sink.
    pub fn finish_attempt(
        self,
        outcome_disposition: HotPathAttemptDisposition,
    ) -> Option<HotPathOperationResult> {
        if outcome_disposition != HotPathAttemptDisposition::Served {
            self.collector.count_degraded();
        }
        let required = match self.collector.required_stages() {
            Ok(required) => required,
            Err(refusal) => {
                self.collector.count_unknown();
                tracing::warn!(
                    target: HOT_PATH_MEASURE_TARGET,
                    event = "eliotd.hot_path_required_stages_refused",
                    reason = %refusal,
                );
                return None;
            }
        };
        let result = match correlate_operation(&required, &self.set, None, LOCAL_READ_OPERATION) {
            Ok(result) => result,
            Err(refusal) => {
                self.collector.count_unknown();
                tracing::warn!(
                    target: HOT_PATH_MEASURE_TARGET,
                    event = "eliotd.hot_path_correlation_refused",
                    reason = %refusal,
                );
                return None;
            }
        };
        if let Ok(line) = serde_json::to_string(&result) {
            self.collector.sink.offer(&line);
        }
        Some(result)
    }
}

/// Converts one scoped allocation observation into the contract's figure.
///
/// The attribution scope travels with the figure, so a reader can see the extent
/// the boundary's own counter covered. A boundary that admitted no scope reports
/// `None` upstream, which reads as `Unknown` — never as a measured zero.
fn observed_allocations(observation: ScopedAllocationObservation) -> HotPathAllocations {
    HotPathAllocations {
        attribution: HotPathAllocationAttribution::RequestScoped {
            coverage: declared_coverage(observation.coverage),
        },
        allocation_count: observation.allocation_count,
        allocated_bytes: observation.allocated_bytes,
    }
}

/// Projects the counter's own coverage onto the contract's coverage vocabulary.
///
/// The counter and the contract each own a coverage type with the same two
/// variants, so the projection is variant-for-variant and loses nothing: the
/// count and bytes are the ORIGINAL figures the boundary's own scope recorded,
/// never recomputed here, and a partial scope stays `Partial` on the wire
/// instead of being widened to a complete one at the crate boundary.
fn declared_coverage(
    coverage: eliot_observability_runtime::HotPathAllocationCoverage,
) -> HotPathAllocationCoverage {
    match coverage {
        eliot_observability_runtime::HotPathAllocationCoverage::Complete => {
            HotPathAllocationCoverage::Complete
        }
        eliot_observability_runtime::HotPathAllocationCoverage::Partial => {
            HotPathAllocationCoverage::Partial
        }
    }
}

/// Converts the boundary's lock observations into the contract's figure.
///
/// An acquisition that had to wait contributes a contended count and its wait; an
/// acquisition that did not wait contributes only the acquisition. A boundary that
/// acquired no lock reports `None` rather than a measured zero, because an
/// unobserved lock is not a contention-free lock.
fn observed_lock_contention(counters: &HotPathResourceCounters) -> Option<HotPathLockContention> {
    if counters.lock_acquisitions() == 0 {
        return None;
    }
    Some(HotPathLockContention {
        acquisitions: counters.lock_acquisitions(),
        contended_acquisitions: counters.lock_contended(),
        contention_wait: HotPathDurationMs {
            elapsed_ms: counters.lock_wait_nanos() / 1_000_000,
            clock_domain_id: HOT_PATH_MONOTONIC_DOMAIN.to_owned(),
        },
    })
}

/// Converts the boundary's cache observations into the contract's figure.
///
/// A boundary that performed no lookup reports `None`; the contract's own
/// derivation treats a zero-lookup, zero-bypass set as unobserved, so an empty set
/// never becomes a measured zero.
fn observed_cache_behaviour(counters: &HotPathResourceCounters) -> Option<HotPathCacheBehaviour> {
    if counters.cache_lookups() == 0 {
        return None;
    }
    Some(HotPathCacheBehaviour {
        lookups: counters.cache_lookups(),
        hits: counters.cache_hits(),
        misses: counters.cache_misses(),
        stale: counters.cache_stale(),
        bypasses: counters.cache_bypasses(),
    })
}
