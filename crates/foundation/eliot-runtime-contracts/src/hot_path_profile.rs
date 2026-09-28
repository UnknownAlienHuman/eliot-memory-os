//! I12.14 hot-path profile and measurement binding contract.
//!
//! I12.14 requires every hot operation to carry a measured queue wait, service
//! time, allocation figure, lock contention figure, cache behaviour figure and
//! degradation rate, and requires a `HotPathProfile` plus an affected product
//! pulse for every crate entering the hot-spine group. The sibling
//! [`crate::hot_path`] module owns the declaration of an operation; this
//! module owns the shape of the measurement that qualifies it.
//!
//! Three properties are structural here rather than advisory:
//!
//! * A measured value only exists inside the `Measured` arm of
//!   [`HotPathObservation`]. An unavailable counter is `Unknown` and an
//!   inapplicable one is `NotApplicable` with a source-backed reason, so
//!   neither can be read as a measured zero.
//! * [`HotPathMetricLabels`] is a closed struct of frozen enums plus the two
//!   identities a manifest registers. Query text, source contents, credentials
//!   and per-user keys are not spellable as a label because no field accepts
//!   them and there is no map to add them to.
//! * [`HotPathProfile::qualifies_manifest`] is the only way to read the
//!   profile/manifest binding, so a profile qualified against one manifest
//!   revision cannot be read as qualifying another.
//!
//! This module declares and checks shapes only. It places no hook, starts no
//! timer, reads no counter, writes no sink and executes no pulse: the
//! boundary hooks, the profiler/counter seam, the bounded sink, the empirical
//! pulse and the readback all belong to the owners the issue names.

use eliot_contracts::{
    ContractVersion, LowercaseSha256, OperationId, RequestId, ResourceGeneration,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::RuntimeContractError;
use crate::hot_path::{HotPathManifest, invalid};

/// Exact wire revision of the versioned hot-path profile and measurement
/// records declared by this module.
pub const HOT_PATH_PROFILE_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Maximum evidence handles one profile names. A profile references its raw run
/// artifacts in the existing evidence sink; it never inlines them.
pub const HOT_PATH_PROFILE_MAX_EVIDENCE_REFS: usize = 8;
/// Maximum declared clock domains one profile may difference readings within.
/// Every duration names one of these domains, so an unbounded domain list would
/// be unbounded metric cardinality.
pub const HOT_PATH_PROFILE_MAX_CLOCK_DOMAINS: usize = 4;
/// Maximum observed invalidation triggers one qualification records.
pub const HOT_PATH_PROFILE_MAX_INVALIDATION_TRIGGERS: usize = 8;

/// The exact `HotPathManifest` revision a profile qualifies or a measurement
/// was taken under.
///
/// The operation/revision pair is the whole binding. A profile qualified
/// against one manifest revision is not readable as qualifying another, because
/// this type has no field that could stand for a different revision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathManifestRevision {
    /// Exact registered operation identity, in the same spelling
    /// `HotPathManifest::operation` uses so the two compare exactly.
    pub operation: String,
    /// Exact wire revision of that operation's manifest.
    pub version: ContractVersion,
}

impl HotPathManifestRevision {
    /// Validates the bound operation identity.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.operation, "operation")
    }
}

/// The bounded-path boundary one measurement record was taken at.
///
/// These are the five boundaries the issue names: admission, claim, start,
/// service end and result return. A replayed stored response is not a sixth
/// boundary; it is [`HotPathObservationKind::Replay`] at the boundary it was
/// served from.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, JsonSchema, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HotPathStage {
    /// Admission of the request into the declared queue.
    Enqueue,
    /// The claim that made the request eligible to run.
    Claim,
    /// The start of service.
    Start,
    /// The end of service.
    ServiceEnd,
    /// Retention or return of the result to the caller.
    ResultReturn,
}

impl HotPathStage {
    /// This boundary's position in the traversal order a hot operation follows.
    ///
    /// The order is fixed by the operation's own shape — admission, eligibility,
    /// start, service end, result return — so a required-stage set is a
    /// duplicate-free ordered subset of exactly these positions and a boundary
    /// can be compared against another without a name comparison.
    #[must_use]
    pub const fn traversal_position(self) -> u8 {
        match self {
            Self::Enqueue => 0,
            Self::Claim => 1,
            Self::Start => 2,
            Self::ServiceEnd => 3,
            Self::ResultReturn => 4,
        }
    }
}

/// Whether a record came from a real execution or from a replayed stored
/// response.
///
/// A replayed stored response is a replay observation, not another execution of
/// the original query, so a replay never enters an execution denominator and
/// never double-counts an execution.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HotPathObservationKind {
    /// The attempt actually executed the operation.
    Execution,
    /// The attempt served a stored response instead of executing.
    Replay,
}

/// Terminal disposition of one execution attempt.
///
/// Every variant here is an attempt that happened. Refusals, timeouts,
/// cancellations and failed attempts stay countable, so none of them can
/// disappear from a latency or degradation denominator.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HotPathAttemptDisposition {
    /// The attempt produced the normal bounded result.
    Served,
    /// Admission or policy refused the attempt.
    Refused,
    /// The attempt exceeded its declared bound and was not served.
    TimedOut,
    /// The caller or an owner cancelled the attempt.
    Cancelled,
    /// The attempt failed.
    Failed,
}

/// Presence state of one required metric category.
///
/// The value exists only in the `Measured` arm. `NotApplicable` carries a
/// source-backed reason and `Unknown` carries nothing at all, so neither can be
/// read as a measured zero. Unavailable instrumentation is `Unknown`, not a
/// measured zero, and an unobserved counter is never reported as zero.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HotPathObservation<T> {
    /// The value was actually observed under the declared attribution.
    Measured(T),
    /// No applicable measurement exists for this category on this path.
    NotApplicable {
        /// Reference to the source that backs the inapplicability.
        reason_ref: String,
    },
    /// Instrumentation was unavailable; the value is unknown, not zero.
    Unknown,
}

impl<T> HotPathObservation<T> {
    /// Validates that an inapplicable category names its source-backed reason.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        match self {
            Self::NotApplicable { reason_ref } => crate::text(reason_ref, "reason_ref"),
            Self::Measured(_) | Self::Unknown => Ok(()),
        }
    }

    /// Whether this observation actually carries a measured value.
    ///
    /// This is the only read a qualification gate may use to decide whether a
    /// required counter was observed. `NotApplicable` and `Unknown` both answer
    /// `false`, so an unobserved counter cannot be mistaken for an observed one
    /// however the record is shaped.
    #[must_use]
    pub fn is_measured(&self) -> bool {
        matches!(self, Self::Measured(_))
    }

    /// The measured value, when this observation carries one.
    #[must_use]
    pub fn as_measured(&self) -> Option<&T> {
        match self {
            Self::Measured(value) => Some(value),
            Self::NotApplicable { .. } | Self::Unknown => None,
        }
    }
}

/// One duration reading in milliseconds, tagged with the single clock domain
/// both of its readings were taken from.
///
/// Unrelated process-local timestamps must not be subtracted, so a duration
/// names its own domain and a difference across two domains is not expressible.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathDurationMs {
    /// Elapsed milliseconds measured within one clock domain.
    pub elapsed_ms: u64,
    /// Exact clock domain both readings were taken from.
    pub clock_domain_id: String,
}

impl HotPathDurationMs {
    /// Validates the bound clock domain identity.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.clock_domain_id, "clock_domain_id")
    }
}

/// One clock domain a profile's readings may be differenced within.
///
/// A new boot invalidates prior monotonic observations, so the boot belongs to
/// the domain identity rather than to a separate reading attribute.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathClockDomain {
    /// Exact identity of the monotonic clock source within the boot.
    pub domain_id: String,
    /// Boot the clock source belongs to.
    pub boot_id: String,
}

impl HotPathClockDomain {
    /// Validates the domain and boot identities.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.domain_id, "domain_id")?;
        crate::text(&self.boot_id, "boot_id")
    }
}

/// Extent of the measured work an allocation attribution actually covered.
///
/// `Partial` means the remainder of the measured path's allocations is
/// unobserved, which is not zero.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HotPathAllocationCoverage {
    /// Every allocation on the measured path was observed under that scope.
    Complete,
    /// Only part of the measured path's allocations was observed.
    Partial,
}

/// The scope an allocation figure was actually attributed to.
///
/// The scope is a variant rather than a field, so a process-wide heap delta
/// cannot be relabelled as per-request allocations: claiming a narrower scope
/// than the counter observed requires naming a variant that counter did not
/// produce. A thread-local scope is a separate variant because async work may
/// outlive the thread the scope was entered on.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HotPathAllocationAttribution {
    /// Counted at the allocation sites inside the measured request scope.
    RequestScoped {
        /// Extent the request scope covered.
        coverage: HotPathAllocationCoverage,
    },
    /// Counted in a thread-local allocator scope that async work may outlive.
    ThreadLocalScope {
        /// Extent the thread-local scope covered.
        coverage: HotPathAllocationCoverage,
    },
    /// A process-wide heap delta, which concurrency makes non-attributable to a
    /// single request.
    ProcessWideHeapDelta {
        /// Extent the process-wide delta covered.
        coverage: HotPathAllocationCoverage,
    },
}

impl HotPathAllocationAttribution {
    /// Rejects a process-wide heap delta that claims to cover one request's
    /// allocations completely, and validates nothing else: the remaining
    /// variants admit either coverage honestly.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        match self {
            Self::ProcessWideHeapDelta {
                coverage: HotPathAllocationCoverage::Complete,
            } => Err(invalid(
                "attribution",
                "a process-wide heap delta cannot cover one request completely",
            )),
            _ => Ok(()),
        }
    }
}

/// Allocation count and bytes observed for one attempt, with the scope that
/// attributed them.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathAllocations {
    /// Scope the counters attributed the figures to.
    pub attribution: HotPathAllocationAttribution,
    /// Observed allocation count under that scope.
    pub allocation_count: u64,
    /// Observed allocated bytes under that scope.
    pub allocated_bytes: u64,
}

impl HotPathAllocations {
    /// Validates the attribution scope and its coverage.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        self.attribution.validate()
    }
}

/// Lock acquisition and contention observed at the actual lock owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathLockContention {
    /// Lock acquisitions observed at the actual lock owner.
    pub acquisitions: u64,
    /// Acquisitions that had to wait for the owner.
    pub contended_acquisitions: u64,
    /// Accumulated wait across the contended acquisitions.
    pub contention_wait: HotPathDurationMs,
}

impl HotPathLockContention {
    /// Validates that contention never exceeds the acquisitions it was drawn
    /// from, and the wait's clock domain.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        if self.contended_acquisitions > self.acquisitions {
            return Err(invalid(
                "contended_acquisitions",
                "must not exceed the observed acquisitions",
            ));
        }
        self.contention_wait.validate()
    }
}

/// Cache lookup outcome counts observed at the actual lookup site.
///
/// The four outcomes are the ones the issue names at lookup: hit, miss, stale
/// and bypass. An unobserved lookup is absent from `lookups`; it is not a miss.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathCacheBehaviour {
    /// Lookups observed at the actual lookup site.
    pub lookups: u64,
    /// Lookups the cache answered.
    pub hits: u64,
    /// Lookups the cache did not hold.
    pub misses: u64,
    /// Lookups answered from a superseded revision.
    pub stale: u64,
    /// Lookups that deliberately skipped the cache.
    pub bypasses: u64,
}

impl HotPathCacheBehaviour {
    /// Validates that no observed outcome class exceeds the lookups it was
    /// drawn from.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        let observed = [
            ("hits", self.hits),
            ("misses", self.misses),
            ("stale", self.stale),
            ("bypasses", self.bypasses),
        ];
        for (field, count) in observed {
            if count > self.lookups {
                return Err(invalid(field, "must not exceed the observed lookups"));
            }
        }
        Ok(())
    }
}

/// The predeclared window a degradation rate is defined over.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathObservationWindow {
    /// Identity of the window that was declared before observation.
    pub window_id: String,
    /// Exact clock domain both boundary readings were taken from.
    pub clock_domain_id: String,
    /// Window start reading in that domain, in milliseconds.
    pub start_ms: u64,
    /// Window end reading in that domain, in milliseconds.
    pub end_ms: u64,
}

impl HotPathObservationWindow {
    /// Validates the window identity, its clock domain, and that the window is
    /// not inverted.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.window_id, "window_id")?;
        crate::text(&self.clock_domain_id, "clock_domain_id")?;
        if self.end_ms < self.start_ms {
            return Err(invalid(
                "end_ms",
                "a declared window must not end before it starts",
            ));
        }
        Ok(())
    }
}

/// The predeclared eligible-operation population a degradation rate covers.
///
/// Every attempt in the population counts, including refusals, timeouts,
/// cancellations and failed attempts. There is deliberately no field that could
/// exclude them, because a population that dropped them would report an
/// unobserved failure as a success.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathEligiblePopulation {
    /// Exact registered operation whose attempts form the population.
    pub operation: String,
    /// Whether the population also contains replayed stored responses, which are
    /// observations rather than executions.
    pub includes_replayed_observations: bool,
}

impl HotPathEligiblePopulation {
    /// Validates the bound operation identity.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.operation, "operation")
    }
}

/// Degradation over a predeclared window and eligible-operation population.
///
/// The rate is `numerator` over `denominator` for the declared window. Numerator,
/// denominator, unknowns and dropped samples are all preserved, so averaging
/// per-class rates is visibly an unweighted average and missing sink data stays
/// visible instead of reading as zero degradation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathDegradationRate {
    /// Predeclared window the rate is defined over.
    pub window: HotPathObservationWindow,
    /// Predeclared eligible-operation population the rate covers.
    pub population: HotPathEligiblePopulation,
    /// Attempts in the window that ended in a declared degradation.
    pub numerator: u64,
    /// Eligible attempts observed in the window.
    pub denominator: u64,
    /// Eligible attempts in the declared population whose outcome was not
    /// observed, including the ones sink loss removed.
    pub unknown: u64,
    /// Metric samples the bounded sink dropped inside the window.
    pub dropped: u64,
}

impl HotPathDegradationRate {
    /// Validates the window, the population, and that degradation never exceeds
    /// the observed population it was drawn from.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        self.window.validate()?;
        self.population.validate()?;
        if self.numerator > self.denominator {
            return Err(invalid(
                "numerator",
                "must not exceed the observed denominator",
            ));
        }
        Ok(())
    }
}

/// Closed, bounded label set for one sampled hot-path metric.
///
/// The set is a struct of frozen enums plus the two identities a manifest
/// registers, not a string map. Query text, source contents, credentials and
/// per-user keys are therefore not spellable as a label: no field accepts them
/// and there is no map to add them to, so the label space of a metric is
/// bounded by the declaration set rather than by observed traffic.
///
/// The request and attempt identities are deliberately absent. They are the
/// correlation keys of one record, not metric dimensions, so per-request
/// cardinality cannot enter the metric namespace. A sample's presence is the
/// [`HotPathObservation`] variant of the category it carries, so an unobserved
/// counter is emitted as an `Unknown` sample rather than as an absent sample or
/// a zero value.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathMetricLabels {
    /// Exact registered operation identity a manifest declares.
    pub operation: String,
    /// Exact owning service a manifest declares for that operation.
    pub owning_service: String,
    /// Boundary the sample was taken at.
    pub stage: HotPathStage,
    /// Whether the sample came from an execution or a replayed response.
    pub observation: HotPathObservationKind,
    /// Terminal disposition of the attempt the sample belongs to.
    pub disposition: HotPathAttemptDisposition,
}

impl HotPathMetricLabels {
    /// Validates the two registered identities a label carries. The remaining
    /// dimensions are frozen enums and admit no free text at all.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.operation, "labels.operation")?;
        crate::text(&self.owning_service, "labels.owning_service")
    }
}

/// The six required metric categories of one hot operation.
///
/// I12.14 requires queue wait, service time, allocations, lock contention,
/// cache behaviour and degradation for every hot operation. All six are
/// present as fields, so a record cannot omit a category: an unobserved counter
/// is `Unknown`, an inapplicable one is a source-backed `NotApplicable`, and
/// neither is a missing field or a measured zero.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathMeasurementMetrics {
    /// Wait from admission to claim.
    pub queue_wait: HotPathObservation<HotPathDurationMs>,
    /// Time the attempt spent being served.
    pub service_time: HotPathObservation<HotPathDurationMs>,
    /// Allocation count and bytes with the scope that attributed them.
    pub allocations: HotPathObservation<HotPathAllocations>,
    /// Lock acquisition and contention at the actual lock owner.
    pub lock_contention: HotPathObservation<HotPathLockContention>,
    /// Cache lookup outcome counts at the actual lookup site.
    pub cache_behaviour: HotPathObservation<HotPathCacheBehaviour>,
    /// Degradation over the predeclared window and population.
    pub degradation: HotPathObservation<HotPathDegradationRate>,
}

impl HotPathMeasurementMetrics {
    /// Validates every category's presence state and, where a value was
    /// measured, the value itself.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        validate_observed(&self.queue_wait, HotPathDurationMs::validate)?;
        validate_observed(&self.service_time, HotPathDurationMs::validate)?;
        validate_observed(&self.allocations, HotPathAllocations::validate)?;
        validate_observed(&self.lock_contention, HotPathLockContention::validate)?;
        validate_observed(&self.cache_behaviour, HotPathCacheBehaviour::validate)?;
        validate_observed(&self.degradation, HotPathDegradationRate::validate)
    }
}

/// One correlated hot-path measurement record for a single execution attempt.
///
/// The record binds the original caller request to the attempt that actually
/// executed it, the process, generation and boot it executed in, the boundary
/// it was taken at, and the manifest and profile revisions in force. That
/// binding is what keeps concurrent attempts and retries from mixing, keeps a
/// replay from counting as another execution, and keeps an unobserved outcome
/// from reading as a success.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathMeasurement {
    /// Closed label set this record's samples are aggregated under.
    pub labels: HotPathMetricLabels,
    /// Identity of the original caller request the attempt serves. A retry of
    /// one request keeps this identity and takes a distinct `attempt_id`.
    pub request_id: RequestId,
    /// Identity of the attempt that actually executed.
    pub attempt_id: OperationId,
    /// Process the attempt executed in.
    pub source_process_id: String,
    /// Module generation the attempt executed under.
    pub source_generation: ResourceGeneration,
    /// Boot the attempt's monotonic readings belong to.
    pub source_boot_id: String,
    /// Manifest revision in force for the attempt.
    pub manifest: HotPathManifestRevision,
    /// Profile revision in force for the attempt.
    pub profile_revision: ContractVersion,
    /// The six required metric categories.
    pub metrics: HotPathMeasurementMetrics,
}

impl HotPathMeasurement {
    /// Validates the label set, the source identity, the bound manifest and
    /// profile revisions, and every metric category.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        self.labels.validate()?;
        crate::text(&self.source_process_id, "source_process_id")?;
        crate::text(&self.source_boot_id, "source_boot_id")?;
        self.manifest.validate()?;
        if self.profile_revision != HOT_PATH_PROFILE_VERSION {
            return Err(invalid(
                "profile_revision",
                "does not match the hot-path profile wire revision",
            ));
        }
        self.metrics.validate()
    }
}

/// The build, target, hardware, operating system and configuration a profile's
/// samples were executed under.
///
/// The build and configuration digests are inputs the producing run supplies;
/// this contract mints neither, so a profile cannot restamp one run's
/// measurements onto another build or configuration.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathBuildEnvironment {
    /// Digest of the exact build the samples ran in.
    pub build_digest: LowercaseSha256,
    /// Target the build produced.
    pub target: String,
    /// Hardware the samples ran on.
    pub hardware: String,
    /// Operating system the samples ran on.
    pub os: String,
    /// Digest of the effective configuration the samples ran under.
    pub configuration_digest: LowercaseSha256,
}

impl HotPathBuildEnvironment {
    /// Validates the declared target, hardware and operating system.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.target, "target")?;
        crate::text(&self.hardware, "hardware")?;
        crate::text(&self.os, "os")
    }
}

/// Declared cache state the samples were executed in.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HotPathCacheState {
    /// Nothing relevant was already resident.
    Cold,
    /// The measured data was already resident.
    Warm,
    /// The path deliberately skipped its cache.
    Bypassed,
}

/// Declared concurrency the samples were executed under.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HotPathConcurrencyCondition {
    /// No other work shared the measured owner.
    Uncontended,
    /// Other work shared the measured owner.
    Contended,
}

/// The workload and cache/concurrency conditions the samples were executed
/// under.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathExecutionConditions {
    /// Declared workload class the sample plan was executed under.
    pub workload_class: String,
    /// Declared cache state the operation was sampled in.
    pub cache_state: HotPathCacheState,
    /// Declared concurrency the samples were executed under.
    pub concurrency: HotPathConcurrencyCondition,
}

impl HotPathExecutionConditions {
    /// Validates the declared workload class.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.workload_class, "workload_class")
    }
}

/// How the samples in a profile were collected.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HotPathCollectionMode {
    /// Collection is off and the governed result is unaffected.
    Disabled,
    /// A declared fraction of attempts is sampled.
    Sampled,
    /// Every attempt is collected.
    Full,
}

/// The sample plan a profile's qualification rests on.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathSamplePlan {
    /// Declared profile class this plan supports.
    pub profile_class: String,
    /// How the samples were collected.
    pub collection_mode: HotPathCollectionMode,
    /// Samples the plan declared it would collect.
    pub declared_samples: u64,
    /// Samples actually retained as evidence.
    pub retained_samples: u64,
    /// Samples the bounded sink dropped.
    pub dropped_samples: u64,
    /// Method used to compare the retained distribution against its baseline.
    pub comparison_method: String,
    /// The collection owner's own measured cost, or `Unknown` when it has not
    /// measured its own overhead.
    pub collection_overhead: HotPathObservation<HotPathDurationMs>,
}

impl HotPathSamplePlan {
    /// Validates the declared workload identity, the sample accounting, and the
    /// collection overhead's presence state.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.profile_class, "profile_class")?;
        crate::text(&self.comparison_method, "comparison_method")?;
        if self.declared_samples == 0 {
            return Err(invalid(
                "declared_samples",
                "a sample plan must declare the samples it intends to collect",
            ));
        }
        if self.retained_samples > self.declared_samples {
            return Err(invalid(
                "retained_samples",
                "must not exceed the declared sample count",
            ));
        }
        validate_observed(&self.collection_overhead, HotPathDurationMs::validate)
    }
}

/// The counter seam a profile's samples were attributed to.
///
/// The issue admits the existing supported profiler/counter seam or an
/// explicitly scoped owned implementation. An ad hoc global allocator
/// replacement is neither, so it is not a variant here.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HotPathCounterAttributionMethod {
    /// The supported profiler/counter seam already present in the process.
    ExistingProfilerCounterSeam,
    /// An implementation explicitly scoped and owned by the measured crate.
    ScopedOwnedCounter,
}

/// The I2.16 `EmpiricalParameter` status of a profile's qualification.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HotPathQualificationStatus {
    /// The candidate value guides planning only.
    Unvalidated,
    /// The value was observed but is not qualified for a profile.
    Observed,
    /// The value is qualified for the declared profile.
    QualifiedForProfile,
    /// A relevant change invalidated the qualification.
    Stale,
    /// The value was rejected.
    Rejected,
}

/// The qualification a profile carries and the instant it expires.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathProfileQualification {
    /// I2.16 status of the qualification.
    pub status: HotPathQualificationStatus,
    /// Wall-clock instant the qualification expires, in milliseconds since the
    /// Unix epoch.
    pub expires_at_ms: u64,
    /// Observed changes that invalidate the qualification, such as changed
    /// dependencies, queue limits, serializer, allocator or profiler, or the
    /// relevant route.
    pub invalidation_triggers: Vec<String>,
}

impl HotPathProfileQualification {
    /// Validates that the qualification expires at a declared instant and names
    /// a bounded, distinct set of invalidation triggers.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        if self.expires_at_ms == 0 {
            return Err(invalid(
                "expires_at_ms",
                "a qualification must expire at a declared instant",
            ));
        }
        validate_texts(
            &self.invalidation_triggers,
            "invalidation_triggers",
            HOT_PATH_PROFILE_MAX_INVALIDATION_TRIGGERS,
        )
    }
}

/// The I12.14 profile of one declared hot operation.
///
/// The ten fields are exactly the ones the issue names: the manifest revision
/// it qualifies, the build, target, hardware, operating system and
/// configuration it was measured under, the crate closure actually observed,
/// the workload and cache/concurrency conditions, the clock domains, the sample
/// plan, the counter attribution method, its evidence references, its
/// qualification and expiry, and the product pulse it affects.
///
/// A profile is not a free-floating record. It names the manifest revision it
/// qualifies, and [`HotPathProfile::qualifies_manifest`] is the only way to read
/// that binding, so a profile qualified against one manifest revision is not
/// readable as qualifying another.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathProfile {
    /// Exact manifest revision this profile qualifies.
    pub manifest: HotPathManifestRevision,
    /// Build, target, hardware, operating system and configuration measured
    /// under.
    pub build_environment: HotPathBuildEnvironment,
    /// Crate closure actually observed, not the closure the manifest declares.
    pub actual_crate_closure: Vec<String>,
    /// Workload and cache/concurrency conditions measured under.
    pub execution_conditions: HotPathExecutionConditions,
    /// Clock domains the readings may be differenced within.
    pub clock_domains: Vec<HotPathClockDomain>,
    /// Sample plan the qualification rests on.
    pub sample_plan: HotPathSamplePlan,
    /// Counter seam the samples were attributed to.
    pub counter_attribution: HotPathCounterAttributionMethod,
    /// References to the raw run artifacts in the existing evidence sink.
    pub evidence_refs: Vec<String>,
    /// Qualification status and expiry.
    pub qualification: HotPathProfileQualification,
    /// Reference to the product pulse this profile affects.
    pub pulse_ref: String,
}

impl HotPathProfile {
    /// Validates the bound manifest revision, the measured build environment,
    /// the observed closure, the execution conditions, the clock domains, the
    /// sample plan, the finite evidence list, the qualification and the pulse.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        self.manifest.validate()?;
        self.build_environment.validate()?;
        validate_crate_closure(&self.actual_crate_closure)?;
        self.execution_conditions.validate()?;
        validate_clock_domains(&self.clock_domains)?;
        self.sample_plan.validate()?;
        if self.evidence_refs.is_empty() {
            return Err(invalid(
                "evidence_refs",
                "a profile must reference the evidence its measurements came from",
            ));
        }
        validate_texts(
            &self.evidence_refs,
            "evidence_refs",
            HOT_PATH_PROFILE_MAX_EVIDENCE_REFS,
        )?;
        self.qualification.validate()?;
        crate::text(&self.pulse_ref, "pulse_ref")
    }

    /// Checks that this profile qualifies exactly the given manifest.
    ///
    /// Both records are validated first, so the closure comparison is a set
    /// comparison over duplicate-free lists. The operation, the manifest
    /// revision, the measured closure and the manifest's own profile reference
    /// are each checked separately and fail with their own variant.
    ///
    /// # Errors
    ///
    /// Returns [`HotPathProfileError`] when either record is invalid, when the
    /// manifest carries no available profile reference, or when the profile's
    /// operation, manifest revision or measured closure is not the manifest's.
    pub fn qualifies_manifest(
        &self,
        manifest: &HotPathManifest,
    ) -> Result<(), HotPathProfileError> {
        self.validate()?;
        manifest.validate()?;
        if !manifest.hot_path_profile_ref.is_available() {
            return Err(HotPathProfileError::ManifestProfileReferenceAbsent);
        }
        if self.manifest.operation != manifest.operation {
            return Err(HotPathProfileError::OperationMismatch);
        }
        if self.manifest.version != manifest.operation_version {
            return Err(HotPathProfileError::ManifestRevisionMismatch);
        }
        if self.actual_crate_closure.len() != manifest.crate_closure.len()
            || manifest
                .crate_closure
                .iter()
                .any(|declared| !self.actual_crate_closure.contains(declared))
        {
            return Err(HotPathProfileError::CrateClosureMismatch);
        }
        Ok(())
    }
}

/// A hot-path profile that does not qualify the manifest it is read against.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HotPathProfileError {
    /// The manifest declares another operation than the profile qualifies.
    #[error("hot-path profile qualifies a different operation than the manifest declares")]
    OperationMismatch,
    /// The profile was qualified against another manifest revision.
    #[error("hot-path profile was qualified against a different manifest revision")]
    ManifestRevisionMismatch,
    /// The measured closure is not the closure the manifest declares.
    #[error("hot-path profile measured a different crate closure than the manifest declares")]
    CrateClosureMismatch,
    /// The manifest carries no available profile reference to qualify.
    #[error("hot-path manifest carries no available profile reference")]
    ManifestProfileReferenceAbsent,
    /// A field of the profile, the manifest or a measurement record is invalid.
    #[error("{0}")]
    Contract(#[from] RuntimeContractError),
}

fn validate_observed<T>(
    observation: &HotPathObservation<T>,
    validate_value: impl FnOnce(&T) -> Result<(), RuntimeContractError>,
) -> Result<(), RuntimeContractError> {
    observation.validate()?;
    match observation {
        HotPathObservation::Measured(value) => validate_value(value),
        HotPathObservation::NotApplicable { .. } | HotPathObservation::Unknown => Ok(()),
    }
}

fn validate_texts(
    values: &[String],
    field: &'static str,
    max: usize,
) -> Result<(), RuntimeContractError> {
    if values.len() > max {
        return Err(invalid(field, "must stay within the bounded item count"));
    }
    for (index, value) in values.iter().enumerate() {
        crate::text(value, field)?;
        if values[..index].iter().any(|previous| previous == value) {
            return Err(invalid(field, "must not repeat an item"));
        }
    }
    Ok(())
}

fn validate_crate_closure(closure: &[String]) -> Result<(), RuntimeContractError> {
    if closure.is_empty() {
        return Err(invalid(
            "actual_crate_closure",
            "must name the closure actually observed",
        ));
    }
    for crate_name in closure {
        crate::text(crate_name, "actual_crate_closure")?;
    }
    for (index, crate_name) in closure.iter().enumerate() {
        if closure[..index]
            .iter()
            .any(|previous| previous == crate_name)
        {
            return Err(invalid("actual_crate_closure", "must not repeat a crate"));
        }
    }
    Ok(())
}

fn validate_clock_domains(domains: &[HotPathClockDomain]) -> Result<(), RuntimeContractError> {
    if domains.is_empty() {
        return Err(invalid(
            "clock_domains",
            "must declare the clock domain its readings come from",
        ));
    }
    if domains.len() > HOT_PATH_PROFILE_MAX_CLOCK_DOMAINS {
        return Err(invalid(
            "clock_domains",
            "must stay within the bounded clock domain count",
        ));
    }
    for (index, domain) in domains.iter().enumerate() {
        domain.validate()?;
        if domains[..index].iter().any(|previous| {
            previous.domain_id == domain.domain_id && previous.boot_id == domain.boot_id
        }) {
            return Err(invalid(
                "clock_domains",
                "must not repeat a clock domain within one boot",
            ));
        }
    }
    Ok(())
}
