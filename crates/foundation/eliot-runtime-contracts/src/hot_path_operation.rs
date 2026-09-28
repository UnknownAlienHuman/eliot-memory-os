//! I12.14 correlated hot-path operation result, required-stage set and
//! observation-derived qualification (issue #1734).
//!
//! [`crate::hot_path`] owns the declaration of a hot operation and
//! [`crate::hot_path_profile`] owns the shape of one measurement and the shape
//! of a profile. Neither can say whether a *set* of stage records for one
//! execution attempt actually forms a complete operation result, nor whether a
//! qualification was earned by observed counters. This module owns exactly
//! those two questions, once, in the same runtime-contract owner.
//!
//! # Four properties are structural here rather than advisory
//!
//! 1. **The expected stage set is independent of the observations.**
//!    [`HotPathRequiredStages::declared_for`] derives the boundary set from the
//!    manifest's declared queue legs, before any record exists, and
//!    [`correlate_operation`] joins against it. A record set that is short
//!    cannot declare itself complete, and a record taken at a boundary the
//!    declaration does not name is reported as an unclaimed stage rather than
//!    silently folded in.
//! 2. **The join key is exact and total.** [`HotPathJoinKey`] is the
//!    `request_id` / `attempt_id` / `stage` / `source_generation` quadruple the
//!    issue names. Two records join only when all four parts match, so
//!    concurrent attempts and retries cannot mix.
//! 3. **The denominator is independent of the numerators.**
//!    [`HotPathPopulationCensus`] counts every attempt the boundary admitted,
//!    including refusals, timeouts, cancellations and failed attempts, and
//!    [`derive_degradation_rate`] divides the degraded count by that admitted
//!    count. An attempt whose outcome was never observed is counted as
//!    `unknown`, so a missing sample can never move the rate toward zero.
//! 4. **Qualification is derived from the observations, never from the shape.**
//!    [`derive_qualification_status`] is a pure function of the correlated
//!    result's six metric categories and the applicability the manifest
//!    declared. A structurally valid record whose applicable counters are all
//!    `Unknown` derives [`HotPathQualificationStatus::Observed`], never
//!    [`HotPathQualificationStatus::QualifiedForProfile`]. This is the exact
//!    substitution the acceptance clause forbids, and it is unrepresentable by
//!    construction rather than by review.
//!
//! This module derives, joins and counts. It starts no clock, reads no counter,
//! writes no sink and runs no pulse: the boundary hooks, the counter seam, the
//! bounded sink, the executed pulse and the readback belong to the owners the
//! issue names.

use eliot_contracts::{ContractVersion, OperationId, RequestId, ResourceGeneration};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::RuntimeContractError;
use crate::hot_path::{HotPathDegradation, HotPathManifest, HotPathQueueDeclaration, invalid};
use crate::hot_path_profile::{
    HOT_PATH_PROFILE_VERSION, HotPathAllocationAttribution, HotPathAllocationCoverage,
    HotPathAllocations, HotPathAttemptDisposition, HotPathBuildEnvironment, HotPathCacheBehaviour,
    HotPathDegradationRate, HotPathDurationMs, HotPathEligiblePopulation, HotPathLockContention,
    HotPathManifestRevision, HotPathMeasurementMetrics, HotPathMetricLabels, HotPathObservation,
    HotPathObservationKind, HotPathObservationWindow, HotPathProfile, HotPathProfileQualification,
    HotPathQualificationStatus, HotPathStage,
};

/// Maximum stage records one operation result will assemble.
///
/// A correlated result is assembled from a *finite* set of boundary records, so
/// the set is bounded. Evidence that exceeds the bound is refused and counted as
/// dropped coverage rather than silently truncated to a plausible subset.
pub const HOT_PATH_OPERATION_MAX_STAGE_RECORDS: usize = 16;

/// Maximum named wait components one stage record may carry.
///
/// Waits inside service are preserved as separately named components rather
/// than subtracted from total service time, so the component list is a bounded
/// set of declared component names.
pub const HOT_PATH_STAGE_MAX_WAIT_COMPONENTS: usize = 8;

/// Queue-identity suffixes the declared result-returning queue legs carry.
///
/// The match is exact on the trailing component of the declared queue identity,
/// so a queue that merely contains one of these substrings is not read as
/// result-returning. These are the queue owners the Kernel's host-request route
/// actually declares for the local-read and campaign-packet legs.
const HOT_PATH_RESULT_RETURNING_QUEUE_SUFFIXES: [&str; 2] = ["local_read", "campaign_packet"];

/// One named wait observed inside the service interval of one stage.
///
/// A wait inside service is a component of service, not a deduction from it.
/// Each component keeps its own name and its own duration in the same declared
/// clock domain as the service interval, so the accounting rule is additive and
/// visible rather than implicit.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathWaitComponent {
    /// Exact declared name of the waited-on condition, such as a lock owner or
    /// a dependency call admitted inside the service interval.
    pub component: String,
    /// Time the service interval spent in this component, in the same declared
    /// clock domain as the service interval itself.
    pub waited: HotPathDurationMs,
}

impl HotPathWaitComponent {
    /// Validates the component name and its clock domain.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.component, "wait_component.component")?;
        self.waited.validate()
    }
}

/// One stage record emitted by a boundary hook at a real owning boundary.
///
/// A stage record is a *finite* observation of one boundary of one execution
/// attempt. It carries the exact join key, the boundary it was taken at, the
/// resource counters the owning boundary could actually observe, any named
/// waits inside its service interval, and the degradation that boundary itself
/// produced.
///
/// A stage record is not a [`crate::hot_path_profile::HotPathMeasurement`]: it
/// names no operation-wide category, so a record that never reaches
/// [`correlate_operation`] contributes nothing to any operation result.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathStageRecord {
    /// The exact join key this record is only ever assembled under.
    pub join: HotPathJoinKey,
    /// Closed label set the record's samples aggregate under.
    pub labels: HotPathMetricLabels,
    /// Process the boundary executed in.
    pub source_process_id: String,
    /// Boot the boundary's monotonic readings belong to.
    pub source_boot_id: String,
    /// Manifest revision in force at the boundary.
    pub manifest: HotPathManifestRevision,
    /// Profile revision in force at the boundary.
    pub profile_revision: ContractVersion,
    /// Wait from admission to this boundary, in one declared clock domain.
    ///
    /// `None` at the enqueue boundary, which *starts* the queue wait and
    /// therefore has nothing to subtract.
    pub queue_wait: Option<HotPathDurationMs>,
    /// Service time this boundary actually performed, in one declared clock
    /// domain. `None` at a boundary that performs no service.
    pub service_time: Option<HotPathDurationMs>,
    /// Allocation count and bytes this boundary's own scoped counter observed,
    /// with the scope that attributed them.
    pub allocations: Option<HotPathAllocations>,
    /// Lock acquisition and contention observed at the actual lock owner this
    /// boundary holds or contends for.
    pub lock_contention: Option<HotPathLockContention>,
    /// Cache lookup outcome counts observed at the actual lookup site.
    pub cache_behaviour: Option<HotPathCacheBehaviour>,
    /// Named waits inside this boundary's service interval, preserved as
    /// components rather than subtracted from service time.
    pub service_wait_components: Vec<HotPathWaitComponent>,
    /// Degradation this boundary itself produced, when it produced one.
    pub degradation: Option<HotPathDegradation>,
}

impl HotPathStageRecord {
    /// Validates the join key, the label set, the source identity, the bound
    /// revisions, and every observed value.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        self.join.validate()?;
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
        if self.join.stage == HotPathStage::Enqueue && self.queue_wait.is_some() {
            return Err(invalid(
                "queue_wait",
                "the enqueue boundary starts the queue wait and cannot observe one",
            ));
        }
        for duration in [self.queue_wait.as_ref(), self.service_time.as_ref()]
            .into_iter()
            .flatten()
        {
            duration.validate()?;
        }
        if let Some(allocations) = &self.allocations {
            allocations.validate()?;
        }
        if let Some(contention) = &self.lock_contention {
            contention.validate()?;
        }
        if let Some(cache) = &self.cache_behaviour {
            cache.validate()?;
        }
        validate_wait_components(&self.service_wait_components)
    }

    /// Whether this record was taken from a replayed stored response rather
    /// than from an execution of the original query.
    #[must_use]
    pub fn is_replay(&self) -> bool {
        self.labels.observation == HotPathObservationKind::Replay
    }
}

/// The exact key one stage record may only be assembled under.
///
/// A stage record joins only when all four parts match: the original caller
/// request, the attempt that executed it, the boundary, and the source
/// generation. A retry keeps the request and takes a distinct attempt, and two
/// concurrent attempts of one request are distinguished by the attempt, so
/// neither can mix.
#[derive(
    Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, JsonSchema, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct HotPathJoinKey {
    /// Identity of the original caller request the attempt serves.
    pub request_id: RequestId,
    /// Identity of the attempt that actually executed.
    pub attempt_id: OperationId,
    /// Boundary the record was taken at.
    pub stage: HotPathStage,
    /// Module generation the boundary executed under.
    pub source_generation: ResourceGeneration,
}

impl HotPathJoinKey {
    /// Validates the two bound identities.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(self.request_id.as_str(), "join.request_id")?;
        crate::text(self.attempt_id.as_str(), "join.attempt_id")
    }
}

/// The boundaries one operation result must be assembled from.
///
/// The set is *independent* of the observations: it is derived from the
/// manifest's declared queue legs before any record exists, so a record set that
/// is short cannot declare itself complete.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathRequiredStages {
    /// Exact registered operation the set is required for.
    pub operation: String,
    /// Boundaries the set requires, in the stage vocabulary's traversal order.
    pub stages: Vec<HotPathStage>,
}

impl HotPathRequiredStages {
    /// Derives the required boundary set from a declared operation.
    ///
    /// Every declared hot operation traverses admission, claim, start and
    /// service end. Result return is required only when the operation declares a
    /// queue that retains and returns a result, because an operation that
    /// declares no such queue produces no retained result to return. Deriving
    /// from the declaration is what keeps the expected set independent of
    /// whichever records happen to exist.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContractError`] when the manifest itself is invalid.
    pub fn declared_for(manifest: &HotPathManifest) -> Result<Self, RuntimeContractError> {
        manifest.validate()?;
        let returns_result = manifest
            .queues_and_capacity
            .iter()
            .any(result_returning_queue);
        let stages = if returns_result {
            vec![
                HotPathStage::Enqueue,
                HotPathStage::Claim,
                HotPathStage::Start,
                HotPathStage::ServiceEnd,
                HotPathStage::ResultReturn,
            ]
        } else {
            vec![
                HotPathStage::Enqueue,
                HotPathStage::Claim,
                HotPathStage::Start,
                HotPathStage::ServiceEnd,
            ]
        };
        Ok(Self {
            operation: manifest.operation.clone(),
            stages,
        })
    }

    /// Validates the operation identity and that the set is a duplicate-free
    /// subset of the stage vocabulary in traversal order.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.operation, "operation")?;
        if self.stages.is_empty() {
            return Err(invalid(
                "stages",
                "a required-stage set must name at least one boundary",
            ));
        }
        for (index, stage) in self.stages.iter().enumerate() {
            if self.stages[..index].contains(stage) {
                return Err(invalid("stages", "must not repeat a boundary"));
            }
            if index > 0
                && stage.traversal_position() <= self.stages[index - 1].traversal_position()
            {
                return Err(invalid(
                    "stages",
                    "must be declared in the stage vocabulary order",
                ));
            }
        }
        Ok(())
    }

    /// Whether this required set includes the given boundary.
    #[must_use]
    pub fn requires(&self, stage: HotPathStage) -> bool {
        self.stages.contains(&stage)
    }
}

/// Whether a declared queue retains and returns a result for a caller.
fn result_returning_queue(queue: &HotPathQueueDeclaration) -> bool {
    HOT_PATH_RESULT_RETURNING_QUEUE_SUFFIXES
        .iter()
        .any(|suffix| queue.queue_id.ends_with(suffix))
}

/// How the correlated result's evidence was assembled.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HotPathEvidenceAssembly {
    /// Every required boundary contributed a stage record and nothing was
    /// refused.
    Complete,
    /// At least one required boundary is absent from the assembled records.
    MissingRequiredStages,
    /// Every required boundary is present, but the bounded set refused at least
    /// one record, so the evidence is not provably complete.
    Truncated,
}

impl HotPathEvidenceAssembly {
    /// Whether the correlated result is backed by a complete record set.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// One correlated hot-path operation result.
///
/// This is the single record the issue's acceptance clause names: one
/// correlated result, possibly assembled from bounded stage records, carrying
/// all six required metric categories with exact units, attribution and
/// coverage, plus its manifest and profile identity through the join key's
/// manifest revision, and the exact product pulse it affects.
///
/// The categories are derived from the joined stage records rather than carried
/// from one of them, so a category that no stage actually observed is `Unknown`
/// here even when some other record happened to spell it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathOperationResult {
    /// Closed label set the result's samples aggregate under.
    pub labels: HotPathMetricLabels,
    /// The exact join key every assembled record shared.
    pub join: HotPathJoinKey,
    /// The boundary set this result was required to be assembled from.
    pub required_stages: HotPathRequiredStages,
    /// How the result's evidence was assembled.
    pub assembly: HotPathEvidenceAssembly,
    /// Required boundaries the assembled records did not include.
    pub missing_stages: Vec<HotPathStage>,
    /// Boundaries present in the assembled records that the required set does
    /// not name.
    pub unclaimed_stages: Vec<HotPathStage>,
    /// Stage records the join actually assembled.
    pub assembled_records: u64,
    /// Stage records the bounded sink dropped or refused for this attempt, so a
    /// refused boundary stays visible instead of reading as never reached.
    pub dropped_records: u64,
    /// The six required metric categories, derived from the joined records and
    /// the window census.
    pub metrics: HotPathMeasurementMetrics,
    /// The degradation reason the joined records observed for this attempt.
    ///
    /// This is the attempt's own bounded outcome, not a rate. A refusal,
    /// timeout, cancellation or failure is visible here and stays counted; a
    /// rate is derived from the window census by [`derive_degradation_rate`].
    pub observed_degradation: Option<HotPathDegradation>,
    /// Named wait components inside service, preserved rather than subtracted.
    pub service_wait_components: Vec<HotPathWaitComponent>,
    /// Exact product pulse this execution affects, so an operation record
    /// resolves to the pulse it was measured for.
    pub pulse_ref: String,
}

impl HotPathOperationResult {
    /// Validates the label set, the join key, the required set, the assembly
    /// state, the named waits and every derived metric category.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        self.labels.validate()?;
        self.join.validate()?;
        self.required_stages.validate()?;
        if self.assembly.is_complete()
            && (!self.missing_stages.is_empty() || !self.unclaimed_stages.is_empty())
        {
            return Err(invalid(
                "assembly",
                "a complete assembly names neither a missing nor an unclaimed boundary",
            ));
        }
        if !self.assembly.is_complete() && self.missing_stages.is_empty() {
            return Err(invalid(
                "missing_stages",
                "an incomplete assembly must name the boundaries it is missing",
            ));
        }
        validate_wait_components(&self.service_wait_components)?;
        if let Some(degradation) = &self.observed_degradation {
            degradation.validate()?;
        }
        crate::text(&self.pulse_ref, "pulse_ref")?;
        self.metrics.validate()
    }

    /// Whether every required boundary was actually assembled and nothing was
    /// refused.
    #[must_use]
    pub fn has_complete_evidence(&self) -> bool {
        self.assembly.is_complete()
    }
}

/// The predeclared census of the eligible-operation population for one window.
///
/// The census is counted at the boundary that admits each attempt, before any
/// outcome is known, so refusals, timeouts, cancellations and failed attempts
/// are in the denominator before they are classified. An attempt whose outcome
/// was never observed is counted in `unknown` rather than omitted, because a
/// sample that never arrived is not a success.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathPopulationCensus {
    /// Predeclared window the census covers.
    pub window: HotPathObservationWindow,
    /// Predeclared eligible-operation population the census covers.
    pub population: HotPathEligiblePopulation,
    /// Eligible attempts the boundary admitted inside the window.
    pub admitted: u64,
    /// Admitted attempts that ended in a declared degradation.
    pub degraded: u64,
    /// Admitted attempts whose outcome was not observed, including the ones
    /// sink loss or a refused join removed.
    pub unknown: u64,
    /// Metric samples the bounded sink dropped inside the window.
    pub dropped: u64,
}

impl HotPathPopulationCensus {
    /// Validates the window, the population, and the census arithmetic.
    ///
    /// `degraded` and `unknown` are both drawn from `admitted`, so neither may
    /// exceed it.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        self.window.validate()?;
        self.population.validate()?;
        if self.degraded > self.admitted {
            return Err(invalid(
                "degraded",
                "must not exceed the admitted population",
            ));
        }
        if self.unknown > self.admitted {
            return Err(invalid(
                "unknown",
                "must not exceed the admitted population",
            ));
        }
        Ok(())
    }
}

/// Derives the degradation rate of one predeclared window from its census.
///
/// The rate is `degraded` over `admitted`. The denominator is the admitted
/// population, not the observed successes and not the observed records, so a
/// refusal, timeout, cancellation or failure stays in the denominator. The
/// unknown count is carried into the rate rather than dropped from it, so
/// missing sink data stays visible instead of collapsing the rate toward zero.
///
/// There is exactly one rate over one population: no per-class rate is
/// computed and none is averaged.
pub fn derive_degradation_rate(
    census: &HotPathPopulationCensus,
) -> Result<HotPathDegradationRate, RuntimeContractError> {
    census.validate()?;
    Ok(HotPathDegradationRate {
        window: census.window.clone(),
        population: census.population.clone(),
        numerator: census.degraded,
        denominator: census.admitted,
        unknown: census.unknown,
        dropped: census.dropped,
    })
}

/// Whether one required metric category applies to a declared operation.
///
/// Applicability is a *declaration*, taken from the manifest before observation,
/// so it is independent of what the collector happened to measure. A category
/// that does not apply is a source-backed declaration rather than an unobserved
/// zero, and only `Applicable` can be satisfied by an observed counter.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HotPathCategoryApplicability {
    /// The category applies to this operation and must be observed before the
    /// qualification can be earned.
    Applicable,
    /// No applicable measurement exists for this category on this path, and the
    /// observation must read `NotApplicable` with its source-backed reason
    /// rather than `Unknown` or a measured zero.
    NotApplicable,
}

impl HotPathCategoryApplicability {
    /// Whether an applicable category's counter must actually be observed.
    #[must_use]
    pub const fn requires_observation(self) -> bool {
        matches!(self, Self::Applicable)
    }
}

/// Which of the six required categories the manifest declares applicable.
///
/// Service time, allocations, cache behaviour and the degradation rate apply to
/// every declared hot operation I12.14 names. Queue wait and lock contention
/// require a declared queue: an operation that declares no queue has no queue
/// owner to wait on and no admitted lock on that path, which is a source-backed
/// inapplicability read off the declaration.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathMetricApplicability {
    /// Queue wait from admission to claim.
    pub queue_wait: HotPathCategoryApplicability,
    /// Service time.
    pub service_time: HotPathCategoryApplicability,
    /// Allocation count and bytes.
    pub allocations: HotPathCategoryApplicability,
    /// Lock acquisition and contention.
    pub lock_contention: HotPathCategoryApplicability,
    /// Cache lookup outcomes.
    pub cache_behaviour: HotPathCategoryApplicability,
    /// A degradation rate over the declared window.
    pub degradation: HotPathCategoryApplicability,
}

impl HotPathMetricApplicability {
    /// Derives the declared applicability of one operation from its manifest.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContractError`] when the manifest itself is invalid.
    pub fn declared_for(manifest: &HotPathManifest) -> Result<Self, RuntimeContractError> {
        manifest.validate()?;
        let queue = if manifest.queues_and_capacity.is_empty() {
            HotPathCategoryApplicability::NotApplicable
        } else {
            HotPathCategoryApplicability::Applicable
        };
        Ok(Self {
            queue_wait: queue,
            service_time: HotPathCategoryApplicability::Applicable,
            allocations: HotPathCategoryApplicability::Applicable,
            lock_contention: queue,
            cache_behaviour: HotPathCategoryApplicability::Applicable,
            degradation: HotPathCategoryApplicability::Applicable,
        })
    }
}

/// Whether the observations behind one correlated result are complete.
///
/// This is the readback the acceptance clause needs: it answers "were the
/// applicable required counters actually observed" from the observations, not
/// from the record's shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HotPathObservationCoverage {
    /// Every applicable required category carries a measured value.
    FullyObserved,
    /// The named applicable required category carries no measured value.
    Unobserved {
        /// Exact category that is declared applicable but unobserved.
        category: &'static str,
    },
}

/// Derives the observation coverage of one correlated result against the
/// declared applicability.
pub fn check_observation_coverage(
    applicability: HotPathMetricApplicability,
    result: &HotPathOperationResult,
) -> HotPathObservationCoverage {
    for (applicable, observed, category) in category_coverage(applicability, result) {
        if applicable.requires_observation() && !observed {
            return HotPathObservationCoverage::Unobserved { category };
        }
    }
    HotPathObservationCoverage::FullyObserved
}

/// Pairs each required category's declared applicability with whether the
/// result actually observed it.
fn category_coverage(
    applicability: HotPathMetricApplicability,
    result: &HotPathOperationResult,
) -> [(HotPathCategoryApplicability, bool, &'static str); 6] {
    [
        (
            applicability.queue_wait,
            result.metrics.queue_wait.is_measured(),
            "queue_wait",
        ),
        (
            applicability.service_time,
            result.metrics.service_time.is_measured(),
            "service_time",
        ),
        (
            applicability.allocations,
            result.metrics.allocations.is_measured(),
            "allocations",
        ),
        (
            applicability.lock_contention,
            result.metrics.lock_contention.is_measured(),
            "lock_contention",
        ),
        (
            applicability.cache_behaviour,
            result.metrics.cache_behaviour.is_measured(),
            "cache_behaviour",
        ),
        (
            applicability.degradation,
            result.metrics.degradation.is_measured(),
            "degradation",
        ),
    ]
}

/// Derives the qualification status of one correlated result.
///
/// This is the whole of the acceptance clause "applicable required counters
/// must be actually observed for full qualification; an all-null structurally
/// valid record is only incomplete progress", expressed as one function of the
/// observations.
///
/// * A category the manifest declares applicable must carry
///   [`HotPathObservation::Measured`] for the result to be
///   [`HotPathQualificationStatus::QualifiedForProfile`]. An `Unknown` there
///   yields [`HotPathQualificationStatus::Observed`], which is I2.16's
///   "observed but not qualified" state: the record is real progress and it is
///   explicitly not a qualification.
/// * A category the manifest does not declare applicable does not block
///   qualification.
/// * Incomplete evidence — a missing required boundary or a refused record —
///   yields [`HotPathQualificationStatus::Observed`] regardless of how complete
///   the metric categories look, because a qualified result over absent evidence
///   is the same overstatement in a different place.
/// * A qualification past its declared expiry instant is
///   [`HotPathQualificationStatus::Stale`], and a rejected qualification stays
///   [`HotPathQualificationStatus::Rejected`].
///
/// A structurally valid record whose applicable counters are all `Unknown`
/// therefore cannot reach `QualifiedForProfile`: no branch of this function
/// reads record shape as evidence.
pub fn derive_qualification_status(
    declared: &HotPathProfileQualification,
    applicability: HotPathMetricApplicability,
    result: &HotPathOperationResult,
    now_ms: u64,
) -> Result<HotPathQualificationStatus, RuntimeContractError> {
    declared.validate()?;
    result.validate()?;
    if declared.status == HotPathQualificationStatus::Rejected {
        return Ok(HotPathQualificationStatus::Rejected);
    }
    if now_ms >= declared.expires_at_ms {
        return Ok(HotPathQualificationStatus::Stale);
    }
    if !result.has_complete_evidence()
        || matches!(
            check_observation_coverage(applicability, result),
            HotPathObservationCoverage::Unobserved { .. }
        )
    {
        return Ok(HotPathQualificationStatus::Observed);
    }
    Ok(HotPathQualificationStatus::QualifiedForProfile)
}

/// The stage records of exactly one operation attempt, as the boundary hooks
/// emit them.
///
/// A stage set is bounded and finite by construction: it holds only the records
/// one attempt contributed, and a record that does not join this attempt's key
/// is refused and counted, so two attempts can never pool their boundaries.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathStageSet {
    /// The key every record in the set must join.
    pub join: HotPathJoinKey,
    /// Records assembled for that exact key.
    pub records: Vec<HotPathStageRecord>,
    /// Records the bounded sink dropped or refused for this attempt.
    pub dropped_records: u64,
}

impl HotPathStageSet {
    /// Admits one stage record to the set.
    ///
    /// A record whose join key is not the set's key is refused: mixing is the
    /// exact failure the join exists to prevent, and the refusal is counted as
    /// dropped coverage rather than absorbed.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContractError`] when the record is invalid, when it
    /// does not join this set's key, when the boundary was already assembled,
    /// or when the bounded record count is already reached.
    pub fn admit(&mut self, record: HotPathStageRecord) -> Result<(), RuntimeContractError> {
        record.validate()?;
        if record.join != self.join {
            self.dropped_records = self.dropped_records.saturating_add(1);
            return Err(invalid(
                "join",
                "a stage record must join the exact request/attempt/stage/generation key",
            ));
        }
        if self.records.len() >= HOT_PATH_OPERATION_MAX_STAGE_RECORDS
            || self
                .records
                .iter()
                .any(|existing| existing.join.stage == record.join.stage)
        {
            self.dropped_records = self.dropped_records.saturating_add(1);
            return Err(invalid(
                "records",
                "must stay within the bounded stage-record count without repeating a boundary",
            ));
        }
        self.records.push(record);
        Ok(())
    }

    /// Validates the set's key and every admitted record.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        self.join.validate()?;
        for record in &self.records {
            record.validate()?;
        }
        Ok(())
    }
}

/// Correlates one attempt's finite stage records into one operation result.
///
/// The join is exact on [`HotPathJoinKey`], so only records the caller admitted
/// under one attempt's key take part, and required-stage coverage is computed
/// against [`HotPathRequiredStages`], which is independent of the records. Each
/// of the five per-attempt categories is derived from the joined records:
///
/// * `queue_wait` is the admission-to-claim wait the claim boundary observed,
///   in the clock domain that boundary observed it in. It is not derived from
///   the start boundary's reading, so no unrelated process-local timestamp is
///   subtracted.
/// * `service_time` is the interval the service boundary observed. The
///   claim-to-start interval is **not** folded into it: a claim lease or a poll
///   interval is not service, and subtracting it without an accounting rule
///   would hide queue behaviour inside a service figure.
/// * `allocations`, `lock_contention` and `cache_behaviour` are summed over the
///   boundaries that actually observed them, each summed figure keeping the
///   attribution scope its own counter declared. A record set that mixed scopes
///   or clock domains is `Unknown` rather than a merged figure: a process-wide
///   heap delta is not relabelled per-request by being added to one.
///
/// The sixth category, `degradation`, is a **rate over a predeclared window**,
/// not a per-attempt figure, so it is the census-derived rate the caller passes
/// in rather than something any single stage record can carry. The per-attempt
/// degradation *reason* the joined records observed is carried separately in
/// `observed_degradation`, so an attempt's outcome is visible on the result
/// without being mistaken for a rate.
///
/// A replayed stored response joins the same way. Because the join key carries
/// the attempt, a replay cannot be assembled into another attempt's result and
/// cannot double-count an execution.
///
/// # Errors
///
/// Returns [`RuntimeContractError`] when the required set, the stage set or the
/// pulse reference is invalid, when the set carries no record to take the
/// attempt's own label set from, when the rate's window does not cover the
/// operation, or when the derived result fails its own validation.
pub fn correlate_operation(
    required: &HotPathRequiredStages,
    set: &HotPathStageSet,
    degradation: Option<HotPathDegradationRate>,
    pulse_ref: &str,
) -> Result<HotPathOperationResult, RuntimeContractError> {
    required.validate()?;
    set.validate()?;
    crate::text(pulse_ref, "pulse_ref")?;
    if let Some(rate) = &degradation {
        rate.validate()?;
        if rate.population.operation != required.operation {
            return Err(invalid(
                "degradation.population.operation",
                "the degradation rate must cover the operation being correlated",
            ));
        }
    }
    let mut assembled = Vec::new();
    let mut missing_stages = Vec::new();
    for stage in &required.stages {
        match set
            .records
            .iter()
            .find(|record| record.join.stage == *stage)
        {
            Some(record) => assembled.push(record),
            None => missing_stages.push(*stage),
        }
    }
    let unclaimed_stages: Vec<HotPathStage> = set
        .records
        .iter()
        .map(|record| record.join.stage)
        .filter(|stage| !required.requires(*stage))
        .collect();
    let assembly = if !missing_stages.is_empty() {
        HotPathEvidenceAssembly::MissingRequiredStages
    } else if set.dropped_records > 0 {
        HotPathEvidenceAssembly::Truncated
    } else {
        HotPathEvidenceAssembly::Complete
    };
    let labels = set.records.first().map_or_else(
        || {
            Err(invalid(
                "labels",
                "an operation result must carry the attempt's own label set",
            ))
        },
        |record| Ok(record.labels.clone()),
    )?;
    let observed_degradation = assembled
        .iter()
        .find_map(|record| record.degradation.clone());
    let result = HotPathOperationResult {
        labels,
        join: set.join.clone(),
        required_stages: required.clone(),
        assembly,
        missing_stages,
        unclaimed_stages,
        assembled_records: u64::try_from(set.records.len()).unwrap_or(u64::MAX),
        dropped_records: set.dropped_records,
        metrics: HotPathMeasurementMetrics {
            queue_wait: derive_duration(assembled.iter().filter_map(|r| r.queue_wait.as_ref())),
            service_time: derive_duration(
                assembled
                    .iter()
                    .filter_map(|record| record.service_time.as_ref()),
            ),
            allocations: derive_allocations(
                assembled
                    .iter()
                    .filter_map(|record| record.allocations.as_ref()),
            ),
            lock_contention: derive_lock_contention(
                assembled
                    .iter()
                    .filter_map(|record| record.lock_contention.as_ref()),
            ),
            cache_behaviour: derive_cache_behaviour(
                assembled
                    .iter()
                    .filter_map(|record| record.cache_behaviour.as_ref()),
            ),
            degradation: degradation
                .map_or(HotPathObservation::Unknown, HotPathObservation::Measured),
        },
        observed_degradation,
        service_wait_components: assembled
            .iter()
            .flat_map(|record| record.service_wait_components.iter())
            .cloned()
            .collect(),
        pulse_ref: pulse_ref.to_owned(),
    };
    result.validate()?;
    Ok(result)
}

/// A correlated result that does not resolve to current evidence, with the
/// exact reason.
///
/// The reason is a value, not prose, so a status readback cannot report a
/// qualified profile over evidence it does not have.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HotPathOperationError {
    /// A field of a required set, stage record, census or result is invalid.
    #[error("{0}")]
    Contract(#[from] RuntimeContractError),
    /// The result does not resolve to the manifest and profile it claims.
    #[error("hot-path operation result does not resolve to its declared manifest and profile")]
    ManifestUnresolved,
    /// The profile was measured under a different build or configuration
    /// identity than the one in force now.
    #[error("hot-path profile evidence is stale against the current build or configuration")]
    StaleEvidence,
    /// An applicable required counter was not observed.
    #[error("hot-path required counter '{category}' was not actually observed")]
    UnobservedCounter {
        /// Exact category that carries no measured value.
        category: &'static str,
    },
}

/// Resolves one correlated result to the manifest, profile and pulse it was
/// measured under, refusing a resolution whose evidence is stale.
///
/// This is the readback the step-7 clause asks for, and it is a real check
/// rather than a flag someone can forget to clear: the profile's measured build
/// environment is compared against the current one, and the qualification is
/// re-derived from the result's own observations. A changed build, dependency
/// closure, queue bound, serializer, allocator/profiler or relevant route
/// therefore cannot be answered with a profile qualified under the earlier
/// identity. A qualification that does not resolve is reported as stale or as
/// an unobserved counter, never as a current qualification.
pub fn resolve_operation_evidence(
    result: &HotPathOperationResult,
    manifest: &HotPathManifest,
    profile: &HotPathProfile,
    current_build: &HotPathBuildEnvironment,
    applicability: HotPathMetricApplicability,
    now_ms: u64,
) -> Result<HotPathProfile, HotPathOperationError> {
    result.validate()?;
    if result.labels.operation != manifest.operation {
        return Err(HotPathOperationError::ManifestUnresolved);
    }
    if profile.qualifies_manifest(manifest).is_err() {
        return Err(HotPathOperationError::ManifestUnresolved);
    }
    if profile.build_environment != *current_build {
        return Err(HotPathOperationError::StaleEvidence);
    }
    let derived =
        derive_qualification_status(&profile.qualification, applicability, result, now_ms)
            .map_err(HotPathOperationError::Contract)?;
    match derived {
        HotPathQualificationStatus::QualifiedForProfile => Ok(profile.clone()),
        _ => {
            if let HotPathObservationCoverage::Unobserved { category } =
                check_observation_coverage(applicability, result)
            {
                Err(HotPathOperationError::UnobservedCounter { category })
            } else {
                Err(HotPathOperationError::StaleEvidence)
            }
        }
    }
}

/// Derives one duration category from the durations the joined records
/// observed.
///
/// A record set in which no boundary observed a duration is `Unknown` rather
/// than a measured zero, and a record set that mixed two clock domains is
/// `Unknown` rather than a sum, because summing across domains would subtract
/// unrelated process-local timestamps.
fn derive_duration<'record>(
    durations: impl Iterator<Item = &'record HotPathDurationMs>,
) -> HotPathObservation<HotPathDurationMs> {
    let mut domain: Option<&str> = None;
    let mut total: u64 = 0;
    for duration in durations {
        match domain {
            Some(existing) if existing != duration.clock_domain_id => {
                return HotPathObservation::Unknown;
            }
            Some(_) => total = total.saturating_add(duration.elapsed_ms),
            None => {
                domain = Some(duration.clock_domain_id.as_str());
                total = duration.elapsed_ms;
            }
        }
    }
    match domain {
        Some(clock_domain_id) => HotPathObservation::Measured(HotPathDurationMs {
            elapsed_ms: total,
            clock_domain_id: clock_domain_id.to_owned(),
        }),
        None => HotPathObservation::Unknown,
    }
}

/// Derives the allocation category from the scoped figures the joined records
/// observed.
///
/// The summed figure keeps a single attribution scope, and a record set that
/// mixed scopes is `Unknown` rather than a merged figure: a process-wide heap
/// delta cannot be relabelled as per-request allocations by being added to one.
fn derive_allocations<'record>(
    allocations: impl Iterator<Item = &'record HotPathAllocations>,
) -> HotPathObservation<HotPathAllocations> {
    let mut attribution: Option<HotPathAllocationAttribution> = None;
    let mut allocation_count: u64 = 0;
    let mut allocated_bytes: u64 = 0;
    for entry in allocations {
        match attribution {
            Some(existing) if existing != entry.attribution => return HotPathObservation::Unknown,
            Some(_) => {
                allocation_count = allocation_count.saturating_add(entry.allocation_count);
                allocated_bytes = allocated_bytes.saturating_add(entry.allocated_bytes);
            }
            None => {
                attribution = Some(entry.attribution);
                allocation_count = entry.allocation_count;
                allocated_bytes = entry.allocated_bytes;
            }
        }
    }
    match attribution {
        Some(attribution) => HotPathObservation::Measured(HotPathAllocations {
            attribution,
            allocation_count,
            allocated_bytes,
        }),
        None => HotPathObservation::Unknown,
    }
}

/// Derives the lock-contention category from the observations the joined
/// boundaries made at their actual lock owners.
fn derive_lock_contention<'record>(
    observations: impl Iterator<Item = &'record HotPathLockContention>,
) -> HotPathObservation<HotPathLockContention> {
    let mut acquisitions: u64 = 0;
    let mut contended: u64 = 0;
    let mut wait: Option<HotPathDurationMs> = None;
    for entry in observations {
        acquisitions = acquisitions.saturating_add(entry.acquisitions);
        contended = contended.saturating_add(entry.contended_acquisitions);
        wait = Some(match wait {
            None => entry.contention_wait.clone(),
            Some(existing) if existing.clock_domain_id != entry.contention_wait.clock_domain_id => {
                return HotPathObservation::Unknown;
            }
            Some(existing) => HotPathDurationMs {
                elapsed_ms: existing
                    .elapsed_ms
                    .saturating_add(entry.contention_wait.elapsed_ms),
                clock_domain_id: existing.clock_domain_id,
            },
        });
    }
    match wait {
        Some(contention_wait) => HotPathObservation::Measured(HotPathLockContention {
            acquisitions,
            contended_acquisitions: contended,
            contention_wait,
        }),
        None => HotPathObservation::Unknown,
    }
}

/// Derives the cache category from the lookup outcomes the joined boundaries
/// observed at their actual lookup sites.
fn derive_cache_behaviour<'record>(
    observations: impl Iterator<Item = &'record HotPathCacheBehaviour>,
) -> HotPathObservation<HotPathCacheBehaviour> {
    let mut total = HotPathCacheBehaviour {
        lookups: 0,
        hits: 0,
        misses: 0,
        stale: 0,
        bypasses: 0,
    };
    for entry in observations {
        total.lookups = total.lookups.saturating_add(entry.lookups);
        total.hits = total.hits.saturating_add(entry.hits);
        total.misses = total.misses.saturating_add(entry.misses);
        total.stale = total.stale.saturating_add(entry.stale);
        total.bypasses = total.bypasses.saturating_add(entry.bypasses);
    }
    if total.lookups == 0 && total.bypasses == 0 {
        return HotPathObservation::Unknown;
    }
    HotPathObservation::Measured(total)
}

fn validate_wait_components(
    components: &[HotPathWaitComponent],
) -> Result<(), RuntimeContractError> {
    if components.len() > HOT_PATH_STAGE_MAX_WAIT_COMPONENTS {
        return Err(invalid(
            "service_wait_components",
            "must stay within the bounded wait-component count",
        ));
    }
    for (index, component) in components.iter().enumerate() {
        component.validate()?;
        if components[..index]
            .iter()
            .any(|previous| previous.component == component.component)
        {
            return Err(invalid(
                "service_wait_components",
                "must not repeat a component name",
            ));
        }
    }
    Ok(())
}

/// The attempt dispositions that count as a declared degradation.
///
/// `Served` is the only non-degradation. A refusal, timeout, cancellation or
/// failure is a degradation, so each of them enters the degradation numerator
/// as well as the denominator and none of them can disappear from either.
#[must_use]
pub const fn is_degraded(disposition: HotPathAttemptDisposition) -> bool {
    !matches!(disposition, HotPathAttemptDisposition::Served)
}

/// The metric labels one attempt's records carry, derived from the owning
/// service's declaration.
///
/// The labels stay the closed struct the profile module defines, so nothing here
/// can add query text, source contents, credentials or a per-user key.
#[must_use]
pub fn attempt_labels(
    manifest: &HotPathManifest,
    stage: HotPathStage,
    observation: HotPathObservationKind,
    disposition: HotPathAttemptDisposition,
) -> HotPathMetricLabels {
    HotPathMetricLabels {
        operation: manifest.operation.clone(),
        owning_service: manifest.owning_service.clone(),
        stage,
        observation,
        disposition,
    }
}

/// Whether an observed allocation figure covers its whole measured scope.
///
/// A figure with partial coverage is not a complete allocation measurement, and
/// a reader that needs completeness checks it here rather than reading a
/// non-zero count as the whole cost.
#[must_use]
pub const fn allocations_are_complete(allocations: &HotPathAllocations) -> bool {
    matches!(
        allocations.attribution,
        HotPathAllocationAttribution::RequestScoped {
            coverage: HotPathAllocationCoverage::Complete
        } | HotPathAllocationAttribution::ThreadLocalScope {
            coverage: HotPathAllocationCoverage::Complete
        }
    )
}
