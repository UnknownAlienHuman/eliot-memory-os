//! Private Kernel memory-pressure coordinator (issue #1685).
//!
//! Architecture `I14.12` (memory pressure), `I14.3` (control reserve), `I14.4`
//! (backpressure), `I14.5` (recovery directive), `I14.28` (effect lifecycle
//! and empirical profiles), `I14.24` (local containment) and `I14.13`
//! (drain/cancellation order).
//!
//! This module owns the pressure-policy/observation/effect join only: a
//! bounded profile, explicit observation states, a lock-free episode state
//! machine with injected time, admission verdicts over the existing front-door
//! partitions, bounded reclamation/containment decision contracts and typed
//! `I14` degradation responses. It performs no sampling or I/O itself, spawns
//! no tasks, holds no control or admission locks, duplicates no reserve
//! accounting (front-door accounting stays with `#1679`), pauses no admission
//! itself and deletes no state. Every outbound effect is a bounded request or
//! intent that the owning runtime delivers: checkpointing to the job owner,
//! eviction to each registered cache owner, payload capture to the Blob owner
//! (`blob_store_controller::BlobStoreController::capture`), containment to the
//! process owner through the existing gateway, restart holds to `#1682`'s
//! restart quarantine, Problem intents to the governed Problem path and
//! degradation responses through the shared `I14` directive vehicle.
//!
//! STITCH (runtime owner): add `mod memory_pressure;` to
//! `bins/eliot-kernel/src/lib.rs`, construct one
//! [`MemoryPressureCoordinator`] in `KernelComposition`, drive
//! [`MemoryPressureCoordinator::observe`] from the existing bounded
//! event/timer loop using
//! [`MemoryPressureCoordinator::next_deadline_ms`], feed platform
//! observations through the existing process-gateway ports as
//! [`MemoryPressureObservation`] values and reconcile owner outcomes via the
//! `record_*` methods. Thresholds are conservative configured hypotheses
//! until qualified (`qualified_proof_ref` is `None` while unqualified): they
//! are not a universal no-OOM promise.

use std::fmt;

use eliot_contracts::{ArtifactId, OperationId};
use eliot_runtime_contracts::{
    AffectedOperationClass, BackpressureDisposition, BottleneckAvailability,
    BottleneckCoverageState, BottleneckObservationV1, CapacityBottleneck, CapacityUnit,
    ControlOperationClass, EarliestRecoveryCondition, EmergencyOperationClass,
    EvidenceCoverageState, HumanActionRequirement, I14_BACKPRESSURE_RESPONSE_VERSION,
    I14AlternativeRoute, I14BackpressureCause, I14BackpressureResponseV1, I14CurrentnessState,
    I14EscalationCondition, I14ForbiddenAction, I14RecoveryAction, I14RecoveryDirectiveV1,
    I14RequiredAuthority, I14ResolutionState, I14WorkOutcome, NormalWorkClass,
    RecoveryCommitStatus, StatePreservationStatus,
};

/// Maximum length of an identity reference, in bytes.
const MAX_ID_LEN: usize = 128;
/// Maximum length of a human-readable reason, in bytes.
const MAX_REASON_LEN: usize = 512;
/// Backstop on episode action records; level-stable identities reuse records
/// instead of growing this log on repeated pressure.
const MAX_EPISODE_ACTIONS: u32 = 64;
/// Maximum registered cache owners asked for bounded eviction.
const MAX_REGISTERED_CACHE_OWNERS: usize = 32;
/// Maximum retained quarantine intents. Quarantine is never silently evicted:
/// a full registry fails closed on new intents.
const MAX_QUARANTINED_GENERATIONS: usize = 32;

/// Returns whether a value is usable as an identity reference.
fn valid_id(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_ID_LEN && !value.chars().any(char::is_control)
}

/// Returns whether a value is usable as a bounded reason.
fn valid_reason(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_REASON_LEN
        && !value.chars().any(char::is_control)
}

/// Typed coordinator failure. Reasons name the violated invariant only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PressureError {
    /// A validated boundary rejected a field.
    InvalidField {
        /// Field that failed validation.
        field: &'static str,
        /// Static invariant that was violated.
        reason: &'static str,
    },
    /// A warranted action is not permitted at the current pressure level.
    ActionNotWarranted {
        /// Action that was refused.
        action: &'static str,
    },
    /// A bounded registry is full; the request fails closed instead of
    /// evicting retained quarantine or owner state.
    RegistryFull {
        /// Registry that refused the insert.
        registry: &'static str,
    },
    /// A value that passed boundary validation failed its contract
    /// constructor. Emitted responses fail closed instead of emitting an
    /// invalid directive.
    InternalInvariant {
        /// Field whose invariant collapsed.
        field: &'static str,
    },
}

impl fmt::Display for PressureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField { field, reason } => {
                write!(formatter, "{field} is invalid: {reason}")
            }
            Self::ActionNotWarranted { action } => {
                write!(formatter, "{action} is not warranted at this level")
            }
            Self::RegistryFull { registry } => {
                write!(formatter, "{registry} registry is full")
            }
            Self::InternalInvariant { field } => {
                write!(formatter, "{field} violated its contract invariant")
            }
        }
    }
}

impl std::error::Error for PressureError {}

/// Which byte counter an observation claims to report.
///
/// Kinds are not interchangeable: a working-set reading never joins a
/// committed-bytes threshold. Which kinds an adapter actually supports is
/// reported per observation through [`MemoryReading::Unsupported`]; an
/// unsupported kind is explicit, never a zero reading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MemoryCounterKind {
    /// Per-process private (non-shareable) committed bytes.
    ProcessPrivate,
    /// Per-process working-set bytes currently resident.
    ProcessWorkingSet,
    /// Job-object committed bytes for the whole contained lineage.
    JobCommitted,
    /// System-wide committed bytes (aggregate scope only).
    SystemCommitted,
}

impl MemoryCounterKind {
    /// Returns the frozen counter name.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessPrivate => "PROCESS_PRIVATE_BYTES",
            Self::ProcessWorkingSet => "PROCESS_WORKING_SET_BYTES",
            Self::JobCommitted => "JOB_COMMITTED_BYTES",
            Self::SystemCommitted => "SYSTEM_COMMITTED_BYTES",
        }
    }

    /// Returns the only unit this counter reports: memory bytes.
    #[must_use]
    pub(crate) const fn unit(self) -> CapacityUnit {
        let _ = self;
        CapacityUnit::MemoryBytes
    }
}

/// Identity scope of one observation. Per-process and per-job readings never
/// join aggregate thresholds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MemoryScope {
    /// One process, bound to its start identity so PID reuse cannot alias it.
    Process {
        /// Process identity reference from the process owner.
        process_ref: String,
        /// Process start identity reference from the process owner.
        start_ref: String,
    },
    /// One contained Job lineage.
    Job {
        /// Job identity reference from the platform owner.
        job_ref: String,
    },
    /// System-wide aggregate reading.
    SystemAggregate,
}

impl MemoryScope {
    /// Validates identity references without performing observation.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for a blank, unbounded or
    /// control-character reference.
    pub(crate) fn validate(&self) -> Result<(), PressureError> {
        match self {
            Self::Process {
                process_ref,
                start_ref,
            } => {
                if !valid_id(process_ref) {
                    return Err(PressureError::InvalidField {
                        field: "scope.process_ref",
                        reason: "must be a bounded non-blank reference",
                    });
                }
                if !valid_id(start_ref) {
                    return Err(PressureError::InvalidField {
                        field: "scope.start_ref",
                        reason: "must be a bounded non-blank reference",
                    });
                }
                Ok(())
            }
            Self::Job { job_ref } => {
                if !valid_id(job_ref) {
                    return Err(PressureError::InvalidField {
                        field: "scope.job_ref",
                        reason: "must be a bounded non-blank reference",
                    });
                }
                Ok(())
            }
            Self::SystemAggregate => Ok(()),
        }
    }

    /// Returns whether this scope aggregates more than one process.
    #[must_use]
    pub(crate) fn is_aggregate(&self) -> bool {
        match self {
            Self::Process { .. } => false,
            Self::Job { .. } | Self::SystemAggregate => true,
        }
    }
}

/// Explicit observation state for one sample.
///
/// Unknown, denied, stale and unsupported metrics are explicit variants, never
/// zero pressure: policy retains the current episode instead of recovering on
/// a non-observed reading.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MemoryReading {
    /// Adapter-observed byte count in the counter's unit.
    Observed {
        /// Observed bytes.
        bytes: u64,
    },
    /// The metric exists but could not be established for this sample.
    Unknown {
        /// Bounded reason the metric is unknown.
        reason: String,
    },
    /// Observation was denied by the owning adapter or policy.
    Denied {
        /// Bounded denial reason.
        reason: String,
    },
    /// The sample is older than the observation's maximum age.
    Stale {
        /// Last observation time in Unix milliseconds.
        last_observed_at_ms: u64,
    },
    /// The adapter does not implement this counter kind or scope.
    Unsupported {
        /// Adapter or counter identity that is unsupported.
        adapter: String,
    },
}

impl MemoryReading {
    /// Validates reason bounds without performing observation.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for a blank, unbounded or
    /// control-character reason.
    pub(crate) fn validate(&self) -> Result<(), PressureError> {
        match self {
            Self::Observed { .. } | Self::Stale { .. } => Ok(()),
            Self::Unknown { reason } | Self::Denied { reason } => {
                if valid_reason(reason) {
                    Ok(())
                } else {
                    Err(PressureError::InvalidField {
                        field: "reading.reason",
                        reason: "must be a bounded non-blank reason",
                    })
                }
            }
            Self::Unsupported { adapter } => {
                if valid_id(adapter) {
                    Ok(())
                } else {
                    Err(PressureError::InvalidField {
                        field: "reading.adapter",
                        reason: "must be a bounded non-blank reference",
                    })
                }
            }
        }
    }

    /// Returns the explicit state of this reading.
    #[must_use]
    pub(crate) const fn state(&self) -> ObservationState {
        match self {
            Self::Observed { .. } => ObservationState::Observed,
            Self::Unknown { .. } => ObservationState::Unknown,
            Self::Denied { .. } => ObservationState::Denied,
            Self::Stale { .. } => ObservationState::Stale,
            Self::Unsupported { .. } => ObservationState::Unsupported,
        }
    }
}

/// Explicit per-sample observation state surfaced to policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObservationState {
    /// Fresh adapter-observed byte count.
    Observed,
    /// Metric could not be established; never zero pressure.
    Unknown,
    /// Observation denied; never zero pressure.
    Denied,
    /// Sample exceeded its maximum age; never zero pressure.
    Stale,
    /// Counter or scope unsupported by the adapter; never zero pressure.
    Unsupported,
}

impl ObservationState {
    /// Returns the frozen state name.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "OBSERVED",
            Self::Unknown => "UNKNOWN",
            Self::Denied => "DENIED",
            Self::Stale => "STALE",
            Self::Unsupported => "UNSUPPORTED",
        }
    }
}

/// One bounded memory-pressure sample consumed through existing platform
/// ports. No sampling, FFI, process spawning or heap logging happens here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MemoryPressureObservation {
    /// Counter kind and unit this sample claims.
    kind: MemoryCounterKind,
    /// Per-process, per-job or aggregate scope.
    scope: MemoryScope,
    /// Owning generation reference binding this sample.
    generation_ref: String,
    /// Boot/session reference distinguishing reuse across restarts.
    boot_ref: String,
    /// Sample time in Unix milliseconds from injected time.
    observed_at_ms: u64,
    /// Maximum sample age in milliseconds; older samples read as stale.
    max_age_ms: u64,
    /// Explicit reading; non-observed states never read as zero pressure.
    reading: MemoryReading,
}

impl MemoryPressureObservation {
    /// Builds one bounded observation without performing I/O.
    #[must_use]
    pub(crate) fn new(
        kind: MemoryCounterKind,
        scope: MemoryScope,
        generation_ref: String,
        boot_ref: String,
        observed_at_ms: u64,
        max_age_ms: u64,
        reading: MemoryReading,
    ) -> Self {
        Self {
            kind,
            scope,
            generation_ref,
            boot_ref,
            observed_at_ms,
            max_age_ms,
            reading,
        }
    }

    /// Returns the counter kind.
    #[must_use]
    pub(crate) fn kind(&self) -> MemoryCounterKind {
        self.kind
    }

    /// Returns the observation scope.
    #[must_use]
    pub(crate) const fn scope(&self) -> &MemoryScope {
        &self.scope
    }

    /// Validates bounds, identity and age configuration.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded reference, a
    /// zero maximum age or an invalid reading.
    pub(crate) fn validate(&self) -> Result<(), PressureError> {
        if !valid_id(&self.generation_ref) {
            return Err(PressureError::InvalidField {
                field: "observation.generation_ref",
                reason: "must be a bounded non-blank reference",
            });
        }
        if !valid_id(&self.boot_ref) {
            return Err(PressureError::InvalidField {
                field: "observation.boot_ref",
                reason: "must be a bounded non-blank reference",
            });
        }
        if self.max_age_ms == 0 {
            return Err(PressureError::InvalidField {
                field: "observation.max_age_ms",
                reason: "must be greater than zero",
            });
        }
        self.scope.validate()?;
        self.reading.validate()
    }

    /// Returns whether the sample is fresh at the injected time.
    #[must_use]
    pub(crate) fn is_fresh(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.observed_at_ms) <= self.max_age_ms
    }

    /// Returns the observed byte count for fresh observed samples, or `None`
    /// for unknown, denied, stale or unsupported metrics. `None` is explicit,
    /// never zero pressure.
    #[must_use]
    pub(crate) fn observed_bytes(&self, now_ms: u64) -> Option<u64> {
        if !self.is_fresh(now_ms) {
            return None;
        }
        match &self.reading {
            MemoryReading::Observed { bytes } => Some(*bytes),
            MemoryReading::Unknown { .. }
            | MemoryReading::Denied { .. }
            | MemoryReading::Stale { .. }
            | MemoryReading::Unsupported { .. } => None,
        }
    }
}

/// Constructor parameters for [`MemoryPressureProfile`]. Thresholds are
/// conservative configured hypotheses until qualified; see
/// [`MemoryPressureProfile::qualified_proof_ref`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MemoryPressureProfileParams {
    /// Stable profile identity.
    pub profile_id: String,
    /// Immutable profile revision; doubles as the directive profile reference.
    pub revision: String,
    /// Exact memory bottleneck dimension from the frozen denominator.
    pub bottleneck: CapacityBottleneck,
    /// Bytes at which background pressure is reported.
    pub warning_bytes: u64,
    /// Bytes at which normal admission selection pauses.
    pub admission_stop_bytes: u64,
    /// Bytes at which durable jobs are asked to checkpoint.
    pub checkpoint_bytes: u64,
    /// Bytes at which over-limit children are contained.
    pub containment_bytes: u64,
    /// Recovery hysteresis in bytes; admission reopens below
    /// `admission_stop_bytes` minus hysteresis.
    pub recovery_hysteresis_bytes: u64,
    /// How long pressure must stay below the recovery band before admission
    /// reopens, in milliseconds.
    pub stable_recovery_interval_ms: u64,
    /// Deadline carried by every outbound pressure action, in milliseconds.
    pub action_deadline_ms: u64,
    /// Backstop on episode action records.
    pub max_actions_per_episode: u32,
    /// Per-owner eviction bound in bytes.
    pub max_eviction_bytes: u64,
    /// Payload-conversion temporary allocation bound in bytes.
    pub max_conversion_bytes: u64,
    /// Protected permits the reserve snapshot must show before admission
    /// reopens; read from front-door accounting, never a local counter.
    pub protected_permits_required: usize,
    /// Independent qualification proof reference, or `None` while the
    /// thresholds remain unqualified hypotheses.
    pub qualified_proof_ref: Option<String>,
}

/// Bounded pressure profile reusing the frozen capacity denominator.
///
/// The bottleneck must use [`CapacityUnit::MemoryBytes`]; the contract rejects
/// any other dimension at construction. Counter kind, scope, generation, boot
/// and age travel on each observation, never on this profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MemoryPressureProfile {
    /// Stable profile identity.
    profile_id: String,
    /// Immutable profile revision.
    revision: String,
    /// Exact memory bottleneck dimension.
    bottleneck: CapacityBottleneck,
    /// Warning threshold in bytes.
    warning_bytes: u64,
    /// Admission-stop threshold in bytes.
    admission_stop_bytes: u64,
    /// Checkpoint threshold in bytes.
    checkpoint_bytes: u64,
    /// Containment threshold in bytes.
    containment_bytes: u64,
    /// Recovery hysteresis in bytes.
    recovery_hysteresis_bytes: u64,
    /// Stable recovery interval in milliseconds.
    stable_recovery_interval_ms: u64,
    /// Outbound action deadline in milliseconds.
    action_deadline_ms: u64,
    /// Backstop on episode action records.
    max_actions_per_episode: u32,
    /// Per-owner eviction bound in bytes.
    max_eviction_bytes: u64,
    /// Payload-conversion temporary allocation bound in bytes.
    max_conversion_bytes: u64,
    /// Protected permits required before admission reopens.
    protected_permits_required: usize,
    /// Qualification proof reference, or `None` while unqualified.
    qualified_proof_ref: Option<String>,
}

impl MemoryPressureProfile {
    /// Builds a validated profile from configuration-supplied values.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded identity, a
    /// non-memory bottleneck, unordered or zero thresholds, a hysteresis that
    /// reaches the admission-stop band, a zero deadline or interval, an
    /// out-of-range action bound, a zero output bound, zero required permits
    /// or an unbounded qualification reference.
    pub(crate) fn new(params: MemoryPressureProfileParams) -> Result<Self, PressureError> {
        if !valid_id(&params.profile_id) {
            return Err(PressureError::InvalidField {
                field: "profile.profile_id",
                reason: "must be a bounded non-blank reference",
            });
        }
        if !valid_id(&params.revision) {
            return Err(PressureError::InvalidField {
                field: "profile.revision",
                reason: "must be a bounded non-blank reference",
            });
        }
        if params.bottleneck.unit() != CapacityUnit::MemoryBytes {
            return Err(PressureError::InvalidField {
                field: "profile.bottleneck",
                reason: "a memory-pressure profile binds a memory-bytes bottleneck",
            });
        }
        Self::validate_thresholds(&params)?;
        Self::validate_output_bounds(&params)?;
        Ok(Self {
            profile_id: params.profile_id,
            revision: params.revision,
            bottleneck: params.bottleneck,
            warning_bytes: params.warning_bytes,
            admission_stop_bytes: params.admission_stop_bytes,
            checkpoint_bytes: params.checkpoint_bytes,
            containment_bytes: params.containment_bytes,
            recovery_hysteresis_bytes: params.recovery_hysteresis_bytes,
            stable_recovery_interval_ms: params.stable_recovery_interval_ms,
            action_deadline_ms: params.action_deadline_ms,
            max_actions_per_episode: params.max_actions_per_episode,
            max_eviction_bytes: params.max_eviction_bytes,
            max_conversion_bytes: params.max_conversion_bytes,
            protected_permits_required: params.protected_permits_required,
            qualified_proof_ref: params.qualified_proof_ref,
        })
    }

    /// Validates the strictly increasing thresholds and the recovery
    /// hysteresis against the admission-stop band.
    fn validate_thresholds(params: &MemoryPressureProfileParams) -> Result<(), PressureError> {
        if params.warning_bytes == 0
            || params.admission_stop_bytes <= params.warning_bytes
            || params.checkpoint_bytes <= params.admission_stop_bytes
            || params.containment_bytes <= params.checkpoint_bytes
        {
            return Err(PressureError::InvalidField {
                field: "profile.thresholds",
                reason: "thresholds are non-zero and strictly increase warning, admission-stop, checkpoint, containment",
            });
        }
        if params.recovery_hysteresis_bytes == 0
            || params.recovery_hysteresis_bytes >= params.admission_stop_bytes
        {
            return Err(PressureError::InvalidField {
                field: "profile.recovery_hysteresis_bytes",
                reason: "hysteresis is non-zero and below the admission-stop band",
            });
        }
        Ok(())
    }

    /// Validates deadlines, output bounds, reserve requirements and the
    /// optional qualification reference.
    fn validate_output_bounds(params: &MemoryPressureProfileParams) -> Result<(), PressureError> {
        if params.stable_recovery_interval_ms == 0 {
            return Err(PressureError::InvalidField {
                field: "profile.stable_recovery_interval_ms",
                reason: "must be greater than zero",
            });
        }
        if params.action_deadline_ms == 0 {
            return Err(PressureError::InvalidField {
                field: "profile.action_deadline_ms",
                reason: "must be greater than zero",
            });
        }
        if params.max_actions_per_episode == 0
            || params.max_actions_per_episode > MAX_EPISODE_ACTIONS
        {
            return Err(PressureError::InvalidField {
                field: "profile.max_actions_per_episode",
                reason: "must be within the bounded episode action backstop",
            });
        }
        if params.max_eviction_bytes == 0 {
            return Err(PressureError::InvalidField {
                field: "profile.max_eviction_bytes",
                reason: "must be greater than zero",
            });
        }
        if params.max_conversion_bytes == 0 {
            return Err(PressureError::InvalidField {
                field: "profile.max_conversion_bytes",
                reason: "must be greater than zero",
            });
        }
        if params.protected_permits_required == 0 {
            return Err(PressureError::InvalidField {
                field: "profile.protected_permits_required",
                reason: "must be greater than zero",
            });
        }
        if params
            .qualified_proof_ref
            .as_ref()
            .is_some_and(|proof| !valid_id(proof))
        {
            return Err(PressureError::InvalidField {
                field: "profile.qualified_proof_ref",
                reason: "must be a bounded non-blank reference when present",
            });
        }
        Ok(())
    }

    /// Returns the stable profile identity.
    #[must_use]
    pub(crate) fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Returns the immutable profile revision.
    #[must_use]
    pub(crate) fn revision(&self) -> &str {
        &self.revision
    }

    /// Returns the exact memory bottleneck dimension.
    #[must_use]
    pub(crate) fn bottleneck(&self) -> CapacityBottleneck {
        self.bottleneck
    }

    /// Returns the admission-stop threshold in bytes.
    #[must_use]
    pub(crate) fn admission_stop_bytes(&self) -> u64 {
        self.admission_stop_bytes
    }

    /// Returns the outbound action deadline in milliseconds.
    #[must_use]
    pub(crate) fn action_deadline_ms(&self) -> u64 {
        self.action_deadline_ms
    }

    /// Returns the per-owner eviction bound in bytes.
    #[must_use]
    pub(crate) fn max_eviction_bytes(&self) -> u64 {
        self.max_eviction_bytes
    }

    /// Returns the payload-conversion temporary allocation bound in bytes.
    #[must_use]
    pub(crate) fn max_conversion_bytes(&self) -> u64 {
        self.max_conversion_bytes
    }

    /// Returns the qualification proof reference, or `None` while the
    /// thresholds remain conservative unqualified hypotheses.
    #[must_use]
    pub(crate) fn qualified_proof_ref(&self) -> Option<&str> {
        self.qualified_proof_ref.as_deref()
    }

    /// Classifies an observed byte count against the configured thresholds.
    #[must_use]
    pub(crate) fn classify(&self, bytes: u64) -> PressureLevel {
        if bytes >= self.containment_bytes {
            PressureLevel::Containment
        } else if bytes >= self.checkpoint_bytes {
            PressureLevel::Checkpoint
        } else if bytes >= self.admission_stop_bytes {
            PressureLevel::AdmissionStop
        } else if bytes >= self.warning_bytes {
            PressureLevel::Warning
        } else {
            PressureLevel::Normal
        }
    }

    /// Returns the recovery ceiling: admission reopens only below this band.
    /// The constructor guarantees the subtraction stays positive.
    #[must_use]
    pub(crate) fn recovery_ceiling(&self) -> u64 {
        self.admission_stop_bytes - self.recovery_hysteresis_bytes
    }
}

/// Classified pressure level for one episode.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum PressureLevel {
    /// Below the warning threshold.
    Normal,
    /// At or above warning: report only.
    Warning,
    /// At or above admission-stop: pause normal selection.
    AdmissionStop,
    /// At or above checkpoint: request durable checkpoints before reclaim.
    Checkpoint,
    /// At or above containment: contain the over-limit child.
    Containment,
}

impl PressureLevel {
    /// Returns the frozen level name.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Warning => "WARNING",
            Self::AdmissionStop => "ADMISSION_STOP",
            Self::Checkpoint => "CHECKPOINT",
            Self::Containment => "CONTAINMENT",
        }
    }

    /// Returns the stable rank used for action identity.
    #[must_use]
    pub(crate) const fn rank(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Warning => 1,
            Self::AdmissionStop => 2,
            Self::Checkpoint => 3,
            Self::Containment => 4,
        }
    }
}

/// Reserve availability snapshot read from front-door accounting.
///
/// Plain data passed by value: the coordinator owns no counter and holds no
/// lock across sampling or I/O. Populate from
/// `FrontDoor::available_normal/protected/emergency`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReserveSnapshot {
    /// Currently available normal-workload permits.
    pub normal_permits: usize,
    /// Currently available protected-control permits.
    pub protected_permits: usize,
    /// Currently available emergency last-resort slots.
    pub emergency_slots: usize,
}

impl ReserveSnapshot {
    /// Returns whether the protected guarantee itself is lost: no protected
    /// and no emergency capacity remains. An enum value or a reserved
    /// percentage is not physically available memory; the existing
    /// last-resort/manual-recovery path owns what happens next.
    #[must_use]
    pub(crate) const fn control_guarantee_lost(self) -> bool {
        self.protected_permits == 0 && self.emergency_slots == 0
    }
}

/// Admission verdict combining observed usage with in-flight reservations so
/// simultaneous admissions cannot each consume the same headroom.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionVerdict {
    /// Admission fits the remaining headroom below admission-stop.
    Admit {
        /// Remaining headroom in bytes after this request.
        headroom_bytes: u64,
    },
    /// Normal selection pauses; protected control is untouched.
    PauseSelection,
    /// The protected guarantee is lost; only the existing
    /// last-resort/manual-recovery path may proceed.
    RefuseControlGuaranteeLost,
}

/// Normal work classes paused under pressure, in contract order.
#[must_use]
pub(crate) const fn paused_normal_classes() -> [NormalWorkClass; 3] {
    [
        NormalWorkClass::NormalBackground,
        NormalWorkClass::ModelJob,
        NormalWorkClass::Swarm,
    ]
}

/// Protected control operations that stay acquirable while normal selection
/// pauses, per `I14.3`. Ordinary work is paused by selection, never relabeled
/// as protected: this list is descriptive and the coordinator owns no path
/// that could move work across partitions.
#[must_use]
pub(crate) const fn protected_operations_preserved() -> [ControlOperationClass; 9] {
    [
        ControlOperationClass::CancelOperation,
        ControlOperationClass::FenceStaleOwner,
        ControlOperationClass::HealthReadinessControl,
        ControlOperationClass::CriticalAttentionTransition,
        ControlOperationClass::ProblemTransition,
        ControlOperationClass::IncidentTransition,
        ControlOperationClass::CriticalTelemetry,
        ControlOperationClass::SafeShutdown,
        ControlOperationClass::Recovery,
    ]
}

/// Evaluates one admission request against level, reserve and reservations.
///
/// # Errors
/// Returns [`PressureError::InvalidField`] for a zero request.
pub(crate) fn evaluate_admission(
    profile: &MemoryPressureProfile,
    level: PressureLevel,
    reserve: ReserveSnapshot,
    observed_bytes: Option<u64>,
    reserved_bytes: u64,
    requested_bytes: u64,
) -> Result<AdmissionVerdict, PressureError> {
    if requested_bytes == 0 {
        return Err(PressureError::InvalidField {
            field: "admission.requested_bytes",
            reason: "must be greater than zero",
        });
    }
    if reserve.control_guarantee_lost() {
        return Ok(AdmissionVerdict::RefuseControlGuaranteeLost);
    }
    if level >= PressureLevel::AdmissionStop {
        return Ok(AdmissionVerdict::PauseSelection);
    }
    let Some(observed) = observed_bytes else {
        // Unknown, denied, stale or unsupported observation is explicit, not
        // zero pressure: headroom cannot be proven, so selection pauses.
        return Ok(AdmissionVerdict::PauseSelection);
    };
    let committed = observed.saturating_add(reserved_bytes);
    let ceiling = profile.admission_stop_bytes();
    if committed.saturating_add(requested_bytes) > ceiling {
        return Ok(AdmissionVerdict::PauseSelection);
    }
    Ok(AdmissionVerdict::Admit {
        headroom_bytes: ceiling.saturating_sub(committed),
    })
}

/// Kind of one bounded pressure action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PressureActionKind {
    /// Pause normal admission selection.
    PauseAdmission,
    /// Ask eligible jobs to checkpoint.
    RequestCheckpoint,
    /// Ask registered cache owners to evict a rebuildable subset.
    RequestReclamation,
    /// Contain the over-limit child through the process owner.
    RequestContainment,
    /// Emit the typed degradation disposition.
    EmitDegradation,
}

impl PressureActionKind {
    /// Returns the frozen action name.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::PauseAdmission => "PAUSE_ADMISSION",
            Self::RequestCheckpoint => "REQUEST_CHECKPOINT",
            Self::RequestReclamation => "REQUEST_RECLAMATION",
            Self::RequestContainment => "REQUEST_CONTAINMENT",
            Self::EmitDegradation => "EMIT_DEGRADATION",
        }
    }
}

/// Lifecycle state of one bounded pressure action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PressureActionState {
    /// Requested; awaiting owner observation.
    Requested,
    /// Owner observed the request.
    Observed,
    /// Owner outcome reconciled into the episode.
    Reconciled,
    /// Deadline passed without reconciliation; never retried automatically.
    Expired,
}

/// One bounded action record with a stable episode-scoped identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PressureActionRecord {
    /// Stable identity `{episode_id}#{level_rank}`.
    action_id: String,
    /// Kind of this action.
    kind: PressureActionKind,
    /// Current lifecycle state.
    state: PressureActionState,
    /// Action deadline in Unix milliseconds from injected time.
    deadline_ms: u64,
}

impl PressureActionRecord {
    /// Returns the stable action identity.
    #[must_use]
    pub(crate) fn action_id(&self) -> &str {
        &self.action_id
    }

    /// Returns the action kind.
    #[must_use]
    pub(crate) fn kind(&self) -> PressureActionKind {
        self.kind
    }

    /// Returns the action state.
    #[must_use]
    pub(crate) fn state(&self) -> PressureActionState {
        self.state
    }
}

/// One open pressure episode with stable identity across repeated samples.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PressureEpisode {
    /// Stable identity `{profile_id}:pressure:{first_seen_ms}`.
    episode_id: String,
    /// Current classified level.
    level: PressureLevel,
    /// First escalation time in Unix milliseconds.
    started_at_ms: u64,
    /// Last observation time in Unix milliseconds.
    last_update_ms: u64,
    /// Bounded action log; identities are level-stable so repeats reuse
    /// records instead of launching duplicate checkpoint/kill loops.
    actions: Vec<PressureActionRecord>,
}

impl PressureEpisode {
    /// Returns the stable episode identity.
    #[must_use]
    pub(crate) fn episode_id(&self) -> &str {
        &self.episode_id
    }

    /// Returns the current level.
    #[must_use]
    pub(crate) fn level(&self) -> PressureLevel {
        self.level
    }

    /// Returns the stable action identity for one level in this episode.
    #[must_use]
    pub(crate) fn action_id_for(&self, level: PressureLevel) -> String {
        format!("{}#{}", self.episode_id, level.rank())
    }
}

/// Bounded per-observation directive. One decision per tick: no accumulating
/// timer tasks, no per-sample process spawning, no full-heap logging.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the five flags are the exact bounded I14.12 pressure actions plus manual recovery; folding them would hide an action"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PressureDirective {
    /// Pause background/model/swarm selection.
    pause_selection: bool,
    /// Request durable checkpoints from eligible jobs.
    request_checkpoint: bool,
    /// Request bounded eviction from registered cache owners.
    request_reclamation: bool,
    /// Contain the over-limit child through the process owner.
    request_containment: bool,
    /// Enter the existing last-resort/manual-recovery path.
    enter_manual_recovery: bool,
    /// Stable action identity for this decision.
    action_id: String,
    /// Decision deadline in Unix milliseconds from injected time.
    deadline_ms: u64,
}

impl PressureDirective {
    /// Returns whether normal selection pauses.
    #[must_use]
    pub(crate) fn pause_selection(&self) -> bool {
        self.pause_selection
    }

    /// Returns whether checkpoints are requested.
    #[must_use]
    pub(crate) fn request_checkpoint(&self) -> bool {
        self.request_checkpoint
    }

    /// Returns whether reclamation is requested.
    #[must_use]
    pub(crate) fn request_reclamation(&self) -> bool {
        self.request_reclamation
    }

    /// Returns whether containment is requested.
    #[must_use]
    pub(crate) fn request_containment(&self) -> bool {
        self.request_containment
    }

    /// Returns whether manual recovery is entered.
    #[must_use]
    pub(crate) fn enter_manual_recovery(&self) -> bool {
        self.enter_manual_recovery
    }

    /// Returns the stable action identity.
    #[must_use]
    pub(crate) fn action_id(&self) -> &str {
        &self.action_id
    }

    /// Returns the decision deadline in Unix milliseconds.
    #[must_use]
    pub(crate) fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }
}

/// Decision for one observation tick.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PressureDecision {
    /// Open episode identity, or `None` when no episode is open.
    episode_id: Option<String>,
    /// Classified or retained level.
    level: PressureLevel,
    /// Explicit observation state; never a hidden healthy default.
    observation: ObservationState,
    /// Bounded directive for this tick.
    directive: PressureDirective,
}

impl PressureDecision {
    /// Returns the open episode identity, if any.
    #[must_use]
    pub(crate) fn episode_id(&self) -> Option<&str> {
        self.episode_id.as_deref()
    }

    /// Returns the decision level.
    #[must_use]
    pub(crate) fn level(&self) -> PressureLevel {
        self.level
    }

    /// Returns the explicit observation state.
    #[must_use]
    pub(crate) fn observation(&self) -> ObservationState {
        self.observation
    }

    /// Returns the bounded directive.
    #[must_use]
    pub(crate) const fn directive(&self) -> &PressureDirective {
        &self.directive
    }
}

/// Cache owner registered for bounded rebuildable-subset eviction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RegisteredCacheOwner {
    /// Owner reference bound at registration.
    owner_ref: String,
}

impl RegisteredCacheOwner {
    /// Returns the owner reference.
    #[must_use]
    pub(crate) fn owner_ref(&self) -> &str {
        &self.owner_ref
    }
}

/// Bounded eviction request to one registered cache owner.
///
/// Only a rebuildable subset may be asked for. Canonical history, unresolved
/// ORS records, receipt/outbox data, referenced checkpoints and sole copies
/// of evidence are unreachable through this type: no variant names them and
/// no method can construct such a request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvictionRequest {
    /// Registered owner reference.
    owner_ref: String,
    /// Maximum bytes the owner may evict for this request.
    max_bytes: u64,
    /// Stable action identity binding this request.
    action_id: String,
    /// Request deadline in Unix milliseconds from injected time.
    deadline_ms: u64,
}

impl EvictionRequest {
    /// Validates bounds without contacting the owner.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded reference, a
    /// zero bound or a zero deadline.
    pub(crate) fn validate(&self) -> Result<(), PressureError> {
        if !valid_id(&self.owner_ref) {
            return Err(PressureError::InvalidField {
                field: "eviction.owner_ref",
                reason: "must be a bounded non-blank reference",
            });
        }
        if self.max_bytes == 0 {
            return Err(PressureError::InvalidField {
                field: "eviction.max_bytes",
                reason: "must be greater than zero",
            });
        }
        if !valid_id(&self.action_id) {
            return Err(PressureError::InvalidField {
                field: "eviction.action_id",
                reason: "must be a bounded non-blank reference",
            });
        }
        if self.deadline_ms == 0 {
            return Err(PressureError::InvalidField {
                field: "eviction.deadline_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }

    /// Returns the registered owner reference.
    #[must_use]
    pub(crate) fn owner_ref(&self) -> &str {
        &self.owner_ref
    }

    /// Returns the maximum evictable bytes.
    #[must_use]
    pub(crate) fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
}

/// Bounded reclamation outcome reported by one cache owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReclamationOutcome {
    /// Reporting owner reference.
    owner_ref: String,
    /// Bytes actually evicted.
    evicted_bytes: u64,
}

impl ReclamationOutcome {
    /// Validates bounds without contacting the owner.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded reference.
    pub(crate) fn validate(&self) -> Result<(), PressureError> {
        if !valid_id(&self.owner_ref) {
            return Err(PressureError::InvalidField {
                field: "reclamation.owner_ref",
                reason: "must be a bounded non-blank reference",
            });
        }
        Ok(())
    }
}

/// Checkpoint request to one eligible job, carrying the original
/// operation/fence identity. The job owner persists the checkpoint and
/// establishes ownership before any planned reclamation or stop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CheckpointRequest {
    /// Eligible job reference.
    job_ref: String,
    /// Original operation reference.
    operation_ref: String,
    /// Original fence reference.
    fence_ref: String,
    /// Stable action identity binding this request.
    action_id: String,
    /// Request deadline in Unix milliseconds from injected time. A
    /// cooperative timeout preserves incomplete/unknown state.
    deadline_ms: u64,
}

impl CheckpointRequest {
    /// Validates bounds without contacting the job owner.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded reference or
    /// a zero deadline.
    pub(crate) fn validate(&self) -> Result<(), PressureError> {
        for (field, value) in [
            ("checkpoint.job_ref", &self.job_ref),
            ("checkpoint.operation_ref", &self.operation_ref),
            ("checkpoint.fence_ref", &self.fence_ref),
            ("checkpoint.action_id", &self.action_id),
        ] {
            if !valid_id(value) {
                return Err(PressureError::InvalidField {
                    field,
                    reason: "must be a bounded non-blank reference",
                });
            }
        }
        if self.deadline_ms == 0 {
            return Err(PressureError::InvalidField {
                field: "checkpoint.deadline_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }

    /// Returns the eligible job reference.
    #[must_use]
    pub(crate) fn job_ref(&self) -> &str {
        &self.job_ref
    }
}

/// Observed checkpoint result. Success, failure and impossibility are
/// separate observed results; none is inferred from the others.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CheckpointOutcome {
    /// Checkpoint persisted under this reference before reclaim/stop.
    Succeeded {
        /// Durable checkpoint reference from the job owner.
        checkpoint_ref: String,
    },
    /// Checkpoint attempted and failed; original state is preserved.
    Failed {
        /// Bounded failure reason.
        reason: String,
    },
    /// Checkpoint impossible for this job; state remains unknown/incomplete.
    Impossible {
        /// Bounded impossibility reason.
        reason: String,
    },
    /// Cooperative timeout elapsed; incomplete/unknown state is preserved.
    TimedOut,
}

impl CheckpointOutcome {
    /// Validates bounds without contacting the job owner.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded reference or
    /// reason.
    pub(crate) fn validate(&self) -> Result<(), PressureError> {
        match self {
            Self::Succeeded { checkpoint_ref } => {
                if valid_id(checkpoint_ref) {
                    Ok(())
                } else {
                    Err(PressureError::InvalidField {
                        field: "checkpoint_outcome.checkpoint_ref",
                        reason: "must be a bounded non-blank reference",
                    })
                }
            }
            Self::Failed { reason } | Self::Impossible { reason } => {
                if valid_reason(reason) {
                    Ok(())
                } else {
                    Err(PressureError::InvalidField {
                        field: "checkpoint_outcome.reason",
                        reason: "must be a bounded non-blank reason",
                    })
                }
            }
            Self::TimedOut => Ok(()),
        }
    }
}

/// Payload-to-handle conversion request. The conversion's own temporary
/// allocations and I/O stay within `max_temp_bytes`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PayloadConversionRequest {
    /// In-memory payload reference.
    payload_ref: String,
    /// Exact payload byte count.
    byte_count: u64,
    /// Scope the captured handle must preserve.
    scope_ref: String,
    /// Privacy the captured handle must preserve.
    privacy_ref: String,
    /// Temporary allocation bound in bytes for this conversion.
    max_temp_bytes: u64,
    /// Stable action identity binding this request.
    action_id: String,
    /// Request deadline in Unix milliseconds from injected time.
    deadline_ms: u64,
}

impl PayloadConversionRequest {
    /// Validates bounds without capturing.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded reference, a
    /// zero byte count, a zero temporary bound or a zero deadline.
    pub(crate) fn validate(&self) -> Result<(), PressureError> {
        for (field, value) in [
            ("conversion.payload_ref", &self.payload_ref),
            ("conversion.scope_ref", &self.scope_ref),
            ("conversion.privacy_ref", &self.privacy_ref),
            ("conversion.action_id", &self.action_id),
        ] {
            if !valid_id(value) {
                return Err(PressureError::InvalidField {
                    field,
                    reason: "must be a bounded non-blank reference",
                });
            }
        }
        if self.byte_count == 0 {
            return Err(PressureError::InvalidField {
                field: "conversion.byte_count",
                reason: "must be greater than zero",
            });
        }
        if self.max_temp_bytes == 0 {
            return Err(PressureError::InvalidField {
                field: "conversion.max_temp_bytes",
                reason: "must be greater than zero",
            });
        }
        if self.deadline_ms == 0 {
            return Err(PressureError::InvalidField {
                field: "conversion.deadline_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Capture verdict reported by the Blob/artifact owner. Failed or unavailable
/// capture carries no handle by construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PayloadCaptureVerdict {
    /// Capture succeeded with independently valid retrieval/lifetime binding.
    Captured {
        /// Durable handle reference from the Blob owner.
        handle_ref: String,
        /// Captured byte count.
        byte_count: u64,
        /// Scope bound to the captured handle.
        scope_ref: String,
        /// Privacy bound to the captured handle.
        privacy_ref: String,
    },
    /// Capture failed or unavailable; the original data is kept.
    Failed {
        /// Bounded failure reason.
        reason: String,
    },
}

impl PayloadCaptureVerdict {
    /// Validates bounds without capturing.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded reference or
    /// reason.
    pub(crate) fn validate(&self) -> Result<(), PressureError> {
        match self {
            Self::Captured {
                handle_ref,
                scope_ref,
                privacy_ref,
                ..
            } => {
                for (field, value) in [
                    ("capture.handle_ref", handle_ref),
                    ("capture.scope_ref", scope_ref),
                    ("capture.privacy_ref", privacy_ref),
                ] {
                    if !valid_id(value) {
                        return Err(PressureError::InvalidField {
                            field,
                            reason: "must be a bounded non-blank reference",
                        });
                    }
                }
                Ok(())
            }
            Self::Failed { reason } => {
                if valid_reason(reason) {
                    Ok(())
                } else {
                    Err(PressureError::InvalidField {
                        field: "capture.reason",
                        reason: "must be a bounded non-blank reason",
                    })
                }
            }
        }
    }
}

/// Released in-memory body after successful capture. Only constructible
/// through [`release_after_capture`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PayloadRelease {
    /// Durable handle now owning the bytes.
    handle_ref: String,
}

impl PayloadRelease {
    /// Returns the durable handle now owning the bytes.
    #[must_use]
    pub(crate) fn handle_ref(&self) -> &str {
        &self.handle_ref
    }
}

/// Why a payload body was not released.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ConversionRefusal {
    /// Capture failed or is unavailable: keep the original data or refuse new
    /// work. Never a placeholder handle.
    KeepOriginal {
        /// Bounded capture failure reason.
        reason: String,
    },
    /// The captured bytes, scope or privacy diverge from the request: the
    /// in-memory body is kept instead of releasing under a wrong binding.
    BindingMismatch,
}

/// Releases the in-memory body only after successful capture with the same
/// bytes, scope and privacy through the Blob/artifact owner.
///
/// # Errors
/// Returns [`ConversionRefusal::KeepOriginal`] for failed or unavailable
/// capture, [`ConversionRefusal::BindingMismatch`] when the captured binding
/// diverges from the request, or [`PressureError::InvalidField`] for an
/// invalid request or verdict.
pub(crate) fn release_after_capture(
    request: &PayloadConversionRequest,
    verdict: &PayloadCaptureVerdict,
) -> Result<PayloadRelease, ConversionReleaseError> {
    request
        .validate()
        .map_err(ConversionReleaseError::Invalid)?;
    verdict
        .validate()
        .map_err(ConversionReleaseError::Invalid)?;
    match verdict {
        PayloadCaptureVerdict::Captured {
            handle_ref,
            byte_count,
            scope_ref,
            privacy_ref,
        } => {
            if *byte_count != request.byte_count
                || *scope_ref != request.scope_ref
                || *privacy_ref != request.privacy_ref
            {
                return Err(ConversionReleaseError::Refused(
                    ConversionRefusal::BindingMismatch,
                ));
            }
            Ok(PayloadRelease {
                handle_ref: handle_ref.clone(),
            })
        }
        PayloadCaptureVerdict::Failed { reason } => Err(ConversionReleaseError::Refused(
            ConversionRefusal::KeepOriginal {
                reason: reason.clone(),
            },
        )),
    }
}

/// Release error joining validation failures with conversion refusals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ConversionReleaseError {
    /// The request or verdict failed boundary validation.
    Invalid(PressureError),
    /// The body is kept: failed capture or binding mismatch.
    Refused(ConversionRefusal),
}

impl fmt::Display for ConversionReleaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(error) => write!(formatter, "conversion input is invalid: {error}"),
            Self::Refused(ConversionRefusal::KeepOriginal { .. }) => {
                write!(formatter, "capture failed; the original data is kept")
            }
            Self::Refused(ConversionRefusal::BindingMismatch) => {
                write!(formatter, "capture binding diverged; the body is kept")
            }
        }
    }
}

impl std::error::Error for ConversionReleaseError {}

/// Already-authorized bounded containment. The coordinator never authorizes
/// containment itself: the process owner presents this proof with the exact
/// generation it covers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContainAuthorization {
    /// Owner that authorized the containment.
    authorizing_owner: String,
    /// Authorization receipt reference.
    authorization: String,
    /// Exact generation covered by this authorization.
    generation: String,
}

impl ContainAuthorization {
    /// Validates bounds without authorizing.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded reference.
    pub(crate) fn validate(&self) -> Result<(), PressureError> {
        for (field, value) in [
            ("authorization.authorizing_owner", &self.authorizing_owner),
            ("authorization.authorization", &self.authorization),
            ("authorization.generation", &self.generation),
        ] {
            if !valid_id(value) {
                return Err(PressureError::InvalidField {
                    field,
                    reason: "must be a bounded non-blank reference",
                });
            }
        }
        Ok(())
    }

    /// Returns whether this authorization covers one generation.
    #[must_use]
    pub(crate) fn authorizes(&self, generation_ref: &str) -> bool {
        self.generation == generation_ref
    }
}

/// Bounded containment request for one emergency over-limit child, executed
/// through the process owner under a presented authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContainRequest {
    /// Over-limit process reference.
    process_ref: String,
    /// Containing Job reference.
    job_ref: String,
    /// Exact generation covered by the authorization.
    generation_ref: String,
    /// Presented authorization receipt reference.
    authorization_ref: String,
    /// Stable action identity binding this request.
    action_id: String,
    /// Request deadline in Unix milliseconds from injected time.
    deadline_ms: u64,
}

impl ContainRequest {
    /// Validates bounds without containing.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded reference or
    /// a zero deadline.
    pub(crate) fn validate(&self) -> Result<(), PressureError> {
        for (field, value) in [
            ("containment.process_ref", &self.process_ref),
            ("containment.job_ref", &self.job_ref),
            ("containment.generation_ref", &self.generation_ref),
            ("containment.authorization_ref", &self.authorization_ref),
            ("containment.action_id", &self.action_id),
        ] {
            if !valid_id(value) {
                return Err(PressureError::InvalidField {
                    field,
                    reason: "must be a bounded non-blank reference",
                });
            }
        }
        if self.deadline_ms == 0 {
            return Err(PressureError::InvalidField {
                field: "containment.deadline_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Observed end state of a contained child. A limit event is not proof the
/// child exited and never proves it is safe to launch its replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ChildEndObservation {
    /// A Job memory-limit event fired but no exit was observed. The child may
    /// still be alive; replacement launch stays fenced by quarantine.
    LimitEventOnly {
        /// Job reference that raised the limit event.
        job_ref: String,
    },
    /// The child exit was observed and reaped with residual ownership noted.
    Exited {
        /// Observed exit code.
        exit_code: i32,
        /// Whether the containing Job is now empty.
        job_empty: bool,
    },
    /// The end state could not be established; effects stay unknown.
    Unknown {
        /// Bounded reason the end state is unknown.
        reason: String,
    },
}

impl ChildEndObservation {
    /// Validates bounds without observing.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded reference or
    /// reason.
    pub(crate) fn validate(&self) -> Result<(), PressureError> {
        match self {
            Self::LimitEventOnly { job_ref } => {
                if valid_id(job_ref) {
                    Ok(())
                } else {
                    Err(PressureError::InvalidField {
                        field: "child_end.job_ref",
                        reason: "must be a bounded non-blank reference",
                    })
                }
            }
            Self::Exited { .. } => Ok(()),
            Self::Unknown { reason } => {
                if valid_reason(reason) {
                    Ok(())
                } else {
                    Err(PressureError::InvalidField {
                        field: "child_end.reason",
                        reason: "must be a bounded non-blank reason",
                    })
                }
            }
        }
    }
}

/// Pending Problem intent retained through the governed path, including
/// across a Store outage that prevents opening or updating the Problem now.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProblemIntent {
    /// Pending Problem reference.
    pending_ref: String,
    /// Whether the intent is retained only because the Store is unavailable.
    store_outage_retained: bool,
}

impl ProblemIntent {
    /// Validates bounds without opening a Problem.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded reference.
    pub(crate) fn validate(&self) -> Result<(), PressureError> {
        if valid_id(&self.pending_ref) {
            Ok(())
        } else {
            Err(PressureError::InvalidField {
                field: "problem.pending_ref",
                reason: "must be a bounded non-blank reference",
            })
        }
    }
}

/// Quarantine intent for one exact generation. The restart owner (`#1682`)
/// consumes the hold instead of immediately restarting into the same
/// pressure; the Problem intent travels the governed path or is retained
/// pending during Store outage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QuarantineIntent {
    /// Exact quarantined generation reference.
    generation_ref: String,
    /// Episode that quarantined it.
    episode_id: String,
    /// Restart hold until this Unix-milliseconds time; a bounded cooldown,
    /// never a duplicate kill loop.
    restart_hold_until_ms: u64,
    /// Governed Problem intent for this quarantine.
    problem: ProblemIntent,
}

impl QuarantineIntent {
    /// Validates bounds without quarantining.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded reference, a
    /// zero hold or an invalid Problem intent.
    pub(crate) fn validate(&self) -> Result<(), PressureError> {
        for (field, value) in [
            ("quarantine.generation_ref", &self.generation_ref),
            ("quarantine.episode_id", &self.episode_id),
        ] {
            if !valid_id(value) {
                return Err(PressureError::InvalidField {
                    field,
                    reason: "must be a bounded non-blank reference",
                });
            }
        }
        if self.restart_hold_until_ms == 0 {
            return Err(PressureError::InvalidField {
                field: "quarantine.restart_hold_until_ms",
                reason: "must be greater than zero",
            });
        }
        self.problem.validate()
    }

    /// Returns whether the restart hold covers the injected time.
    #[must_use]
    pub(crate) fn is_holding(&self, now_ms: u64) -> bool {
        now_ms < self.restart_hold_until_ms
    }
}

/// Separately observed episode results. Checkpoint requested, memory
/// reclaimed, process stopped and effects reconciled never collapse into one
/// flag: each is recorded only from its owner's observation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct EpisodeReconciliation {
    /// Latest checkpoint outcome, when a checkpoint was requested.
    checkpoint: Option<CheckpointOutcome>,
    /// Total bytes owners reported reclaimed this episode.
    reclaimed_bytes: u64,
    /// Latest containment end observation, when containment ran.
    containment: Option<ChildEndObservation>,
    /// Whether external effects were reconciled by their owner. Set only by
    /// [`MemoryPressureCoordinator::record_effects_reconciled`]; recovery
    /// never clears it.
    effects_reconciled: bool,
}

impl EpisodeReconciliation {
    /// Returns the latest checkpoint outcome, if any.
    #[must_use]
    pub(crate) const fn checkpoint(&self) -> Option<&CheckpointOutcome> {
        self.checkpoint.as_ref()
    }

    /// Returns the total reclaimed bytes reported this episode.
    #[must_use]
    pub(crate) fn reclaimed_bytes(&self) -> u64 {
        self.reclaimed_bytes
    }

    /// Returns the latest containment observation, if any.
    #[must_use]
    pub(crate) const fn containment(&self) -> Option<&ChildEndObservation> {
        self.containment.as_ref()
    }

    /// Returns whether effects were reconciled.
    #[must_use]
    pub(crate) fn effects_reconciled(&self) -> bool {
        self.effects_reconciled
    }
}

/// Private Kernel pressure coordinator.
///
/// A lock-free episode state machine over injected time: policy methods take
/// `now_ms`, hold no locks across sampling or I/O, spawn nothing and perform
/// no I/O. Recovery requires the profile's stable interval below the recovery
/// band with the required protected permits visible; quarantine, unknown
/// effects and reservations are never cleared because a sample fell below a
/// threshold — no method exists that could clear them on that signal.
pub(crate) struct MemoryPressureCoordinator {
    /// Validated configured profile.
    profile: MemoryPressureProfile,
    /// Open episode, if any.
    episode: Option<PressureEpisode>,
    /// First time below the recovery band during an open episode, if any.
    below_band_since_ms: Option<u64>,
    /// Cache owners registered for bounded eviction.
    cache_owners: Vec<RegisteredCacheOwner>,
    /// Retained quarantine intents; never auto-cleared by recovery.
    quarantines: Vec<QuarantineIntent>,
    /// Separately observed episode results.
    reconciliation: EpisodeReconciliation,
}

impl MemoryPressureCoordinator {
    /// Creates a coordinator from a validated profile.
    #[must_use]
    pub(crate) const fn new(profile: MemoryPressureProfile) -> Self {
        Self {
            profile,
            episode: None,
            below_band_since_ms: None,
            cache_owners: Vec::new(),
            quarantines: Vec::new(),
            reconciliation: EpisodeReconciliation {
                checkpoint: None,
                reclaimed_bytes: 0,
                containment: None,
                effects_reconciled: false,
            },
        }
    }

    /// Returns the configured profile.
    #[must_use]
    pub(crate) const fn profile(&self) -> &MemoryPressureProfile {
        &self.profile
    }

    /// Returns the open episode, if any.
    #[must_use]
    pub(crate) const fn episode(&self) -> Option<&PressureEpisode> {
        self.episode.as_ref()
    }

    /// Returns the retained quarantine intents.
    #[must_use]
    pub(crate) fn quarantines(&self) -> &[QuarantineIntent] {
        &self.quarantines
    }

    /// Returns the separately observed episode results.
    #[must_use]
    pub(crate) const fn reconciliation(&self) -> &EpisodeReconciliation {
        &self.reconciliation
    }

    /// Registers one cache owner for bounded rebuildable-subset eviction.
    /// Registration is idempotent per owner reference.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded reference or
    /// [`PressureError::RegistryFull`] when the bounded registry is full.
    pub(crate) fn register_cache_owner(&mut self, owner_ref: &str) -> Result<(), PressureError> {
        if !valid_id(owner_ref) {
            return Err(PressureError::InvalidField {
                field: "cache_owner.owner_ref",
                reason: "must be a bounded non-blank reference",
            });
        }
        if self
            .cache_owners
            .iter()
            .any(|owner| owner.owner_ref == owner_ref)
        {
            return Ok(());
        }
        if self.cache_owners.len() >= MAX_REGISTERED_CACHE_OWNERS {
            return Err(PressureError::RegistryFull {
                registry: "cache_owner",
            });
        }
        self.cache_owners.push(RegisteredCacheOwner {
            owner_ref: owner_ref.to_owned(),
        });
        Ok(())
    }

    /// Observes one tick and returns the bounded decision.
    ///
    /// Observed bytes classify immediately; unknown, denied, stale and
    /// unsupported readings retain the current episode without escalating or
    /// recovering and never open an episode. Recovery closes the episode only
    /// after the stable interval below the recovery band with the required
    /// protected permits visible. Repeated pressure reuses the level-stable
    /// action identity instead of recording duplicate actions.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an invalid observation.
    pub(crate) fn observe(
        &mut self,
        observation: &MemoryPressureObservation,
        reserve: ReserveSnapshot,
        now_ms: u64,
    ) -> Result<PressureDecision, PressureError> {
        observation.validate()?;
        let state = observation.reading.state();
        let bytes = observation.observed_bytes(now_ms);
        let enter_manual_recovery = reserve.control_guarantee_lost();

        let level = match (state, bytes) {
            (ObservationState::Observed, Some(observed)) => {
                let classified = self.profile.classify(observed);
                self.track_episode(classified, now_ms);
                self.track_recovery(observed, reserve, now_ms);
                self.current_level()
            }
            _ => self.current_level(),
        };

        let episode_id = self
            .episode
            .as_ref()
            .map(|episode| episode.episode_id.clone());
        let action_id = episode_id.as_ref().map_or_else(
            || format!("{}#{}", self.profile.profile_id(), level.rank()),
            |episode| format!("{episode}#{}", level.rank()),
        );
        let deadline_ms = now_ms.saturating_add(self.profile.action_deadline_ms());
        self.record_level_action(&action_id, level, deadline_ms);

        Ok(PressureDecision {
            episode_id,
            level,
            observation: state,
            directive: PressureDirective {
                pause_selection: level >= PressureLevel::AdmissionStop,
                request_checkpoint: level >= PressureLevel::Checkpoint,
                request_reclamation: level >= PressureLevel::Checkpoint,
                request_containment: level >= PressureLevel::Containment,
                enter_manual_recovery,
                action_id,
                deadline_ms,
            },
        })
    }

    /// Returns the next time the runtime loop must drive this coordinator, or
    /// `None` when no episode constrains the loop. Pure computation over
    /// injected time: the coordinator owns no timer.
    #[must_use]
    pub(crate) fn next_deadline_ms(&self, now_ms: u64) -> Option<u64> {
        let episode = self.episode.as_ref()?;
        let mut deadline = episode
            .last_update_ms
            .saturating_add(self.profile.stable_recovery_interval_ms.max(1));
        for action in &episode.actions {
            if action.state == PressureActionState::Requested && action.deadline_ms > now_ms {
                deadline = deadline.min(action.deadline_ms);
            }
        }
        Some(deadline)
    }

    /// Builds a bounded eviction request for one registered cache owner.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unregistered or
    /// unbounded owner, an unbounded action identity or a zero time, or
    /// [`PressureError::ActionNotWarranted`] when no episode warrants reclaim.
    pub(crate) fn eviction_request(
        &self,
        owner_ref: &str,
        action_id: &str,
        now_ms: u64,
    ) -> Result<EvictionRequest, PressureError> {
        if !self
            .cache_owners
            .iter()
            .any(|owner| owner.owner_ref == owner_ref)
        {
            return Err(PressureError::InvalidField {
                field: "eviction.owner_ref",
                reason: "owner is not registered for bounded eviction",
            });
        }
        if !valid_id(action_id) {
            return Err(PressureError::InvalidField {
                field: "eviction.action_id",
                reason: "must be a bounded non-blank reference",
            });
        }
        if now_ms == 0 {
            return Err(PressureError::InvalidField {
                field: "eviction.now_ms",
                reason: "must be greater than zero",
            });
        }
        match self.episode.as_ref().map(|episode| episode.level) {
            Some(
                PressureLevel::Checkpoint
                | PressureLevel::Containment
                | PressureLevel::AdmissionStop,
            ) => {}
            _ => {
                return Err(PressureError::ActionNotWarranted { action: "eviction" });
            }
        }
        Ok(EvictionRequest {
            owner_ref: owner_ref.to_owned(),
            max_bytes: self.profile.max_eviction_bytes(),
            action_id: action_id.to_owned(),
            deadline_ms: now_ms.saturating_add(self.profile.action_deadline_ms()),
        })
    }

    /// Builds a checkpoint request carrying the original operation and fence.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded reference or
    /// zero time, or [`PressureError::ActionNotWarranted`] below the
    /// checkpoint level.
    pub(crate) fn checkpoint_request(
        &self,
        job_ref: &str,
        operation_ref: &str,
        fence_ref: &str,
        action_id: &str,
        now_ms: u64,
    ) -> Result<CheckpointRequest, PressureError> {
        for (field, value) in [
            ("checkpoint.job_ref", job_ref),
            ("checkpoint.operation_ref", operation_ref),
            ("checkpoint.fence_ref", fence_ref),
            ("checkpoint.action_id", action_id),
        ] {
            if !valid_id(value) {
                return Err(PressureError::InvalidField {
                    field,
                    reason: "must be a bounded non-blank reference",
                });
            }
        }
        if now_ms == 0 {
            return Err(PressureError::InvalidField {
                field: "checkpoint.now_ms",
                reason: "must be greater than zero",
            });
        }
        match self.episode.as_ref().map(|episode| episode.level) {
            Some(PressureLevel::Checkpoint | PressureLevel::Containment) => {}
            _ => {
                return Err(PressureError::ActionNotWarranted {
                    action: "checkpoint",
                });
            }
        }
        Ok(CheckpointRequest {
            job_ref: job_ref.to_owned(),
            operation_ref: operation_ref.to_owned(),
            fence_ref: fence_ref.to_owned(),
            action_id: action_id.to_owned(),
            deadline_ms: now_ms.saturating_add(self.profile.action_deadline_ms()),
        })
    }

    /// Builds a payload-conversion request bounded by the profile's temporary
    /// allocation ceiling.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded reference, a
    /// zero byte count, a temporary bound above the profile ceiling or a zero
    /// time.
    ///
    /// Live status: no production caller. Measured on this tree, no code
    /// outside this module names this method (the defining line is its only
    /// reference), and this module is not yet declared in
    /// `bins/eliot-kernel/src/lib.rs` at all — see the module-level STITCH note
    /// — so the entry is not even compiled into the binary. Its product
    /// [`PayloadConversionRequest`] is likewise unreachable: this constructor is
    /// its only producer, and its only consumer, `release_after_capture`, is
    /// itself uncalled, so `PayloadConversionRequest::validate` runs only from
    /// that uncalled consumer. Nothing in the repository builds a payload
    /// conversion request; whether a runtime owner wires this request to the
    /// Blob/artifact capture owner or retires it is an owner decision.
    #[allow(
        clippy::too_many_arguments,
        reason = "the conversion binds one explicit field per payload/scope/privacy/budget/identity dimension and must stay explicit"
    )]
    pub(crate) fn conversion_request(
        &self,
        payload_ref: &str,
        byte_count: u64,
        scope_ref: &str,
        privacy_ref: &str,
        max_temp_bytes: u64,
        action_id: &str,
        now_ms: u64,
    ) -> Result<PayloadConversionRequest, PressureError> {
        for (field, value) in [
            ("conversion.payload_ref", payload_ref),
            ("conversion.scope_ref", scope_ref),
            ("conversion.privacy_ref", privacy_ref),
            ("conversion.action_id", action_id),
        ] {
            if !valid_id(value) {
                return Err(PressureError::InvalidField {
                    field,
                    reason: "must be a bounded non-blank reference",
                });
            }
        }
        if byte_count == 0 {
            return Err(PressureError::InvalidField {
                field: "conversion.byte_count",
                reason: "must be greater than zero",
            });
        }
        if max_temp_bytes == 0 || max_temp_bytes > self.profile.max_conversion_bytes() {
            return Err(PressureError::InvalidField {
                field: "conversion.max_temp_bytes",
                reason: "must be within the profile conversion ceiling",
            });
        }
        if now_ms == 0 {
            return Err(PressureError::InvalidField {
                field: "conversion.now_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(PayloadConversionRequest {
            payload_ref: payload_ref.to_owned(),
            byte_count,
            scope_ref: scope_ref.to_owned(),
            privacy_ref: privacy_ref.to_owned(),
            max_temp_bytes,
            action_id: action_id.to_owned(),
            deadline_ms: now_ms.saturating_add(self.profile.action_deadline_ms()),
        })
    }

    /// Builds a bounded containment request under a presented authorization
    /// covering the exact generation.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an invalid authorization
    /// or unbounded reference, or [`PressureError::ActionNotWarranted`] below
    /// the containment level or when the authorization covers a different
    /// generation.
    pub(crate) fn contain_request(
        &self,
        process_ref: &str,
        job_ref: &str,
        generation_ref: &str,
        authorization: &ContainAuthorization,
        action_id: &str,
        now_ms: u64,
    ) -> Result<ContainRequest, PressureError> {
        authorization.validate()?;
        for (field, value) in [
            ("containment.process_ref", process_ref),
            ("containment.job_ref", job_ref),
            ("containment.generation_ref", generation_ref),
            ("containment.action_id", action_id),
        ] {
            if !valid_id(value) {
                return Err(PressureError::InvalidField {
                    field,
                    reason: "must be a bounded non-blank reference",
                });
            }
        }
        if now_ms == 0 {
            return Err(PressureError::InvalidField {
                field: "containment.now_ms",
                reason: "must be greater than zero",
            });
        }
        if !authorization.authorizes(generation_ref) {
            return Err(PressureError::InvalidField {
                field: "containment.authorization",
                reason: "authorization does not cover this generation",
            });
        }
        if self.episode.as_ref().map(|episode| episode.level) != Some(PressureLevel::Containment) {
            return Err(PressureError::ActionNotWarranted {
                action: "containment",
            });
        }
        Ok(ContainRequest {
            process_ref: process_ref.to_owned(),
            job_ref: job_ref.to_owned(),
            generation_ref: generation_ref.to_owned(),
            authorization_ref: authorization.authorization.clone(),
            action_id: action_id.to_owned(),
            deadline_ms: now_ms.saturating_add(self.profile.action_deadline_ms()),
        })
    }

    /// Records a checkpoint outcome into the separate observed results and
    /// reconciles the matching action.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an invalid outcome.
    pub(crate) fn record_checkpoint_outcome(
        &mut self,
        outcome: CheckpointOutcome,
    ) -> Result<(), PressureError> {
        outcome.validate()?;
        self.reconciliation.checkpoint = Some(outcome);
        self.reconcile_action(PressureActionKind::RequestCheckpoint);
        Ok(())
    }

    /// Records a reclamation outcome: bytes add to the reclaimed total only
    /// from the owner's report, never inferred.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an invalid outcome.
    pub(crate) fn record_reclamation_outcome(
        &mut self,
        outcome: &ReclamationOutcome,
    ) -> Result<(), PressureError> {
        outcome.validate()?;
        self.reconciliation.reclaimed_bytes = self
            .reconciliation
            .reclaimed_bytes
            .saturating_add(outcome.evicted_bytes);
        self.reconcile_action(PressureActionKind::RequestReclamation);
        Ok(())
    }

    /// Records a containment end observation. A limit-only event stays a
    /// limit-only event: it never becomes an exit claim here.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an invalid observation.
    pub(crate) fn record_containment_outcome(
        &mut self,
        observation: ChildEndObservation,
    ) -> Result<(), PressureError> {
        observation.validate()?;
        self.reconciliation.containment = Some(observation);
        self.reconcile_action(PressureActionKind::RequestContainment);
        Ok(())
    }

    /// Records owner-reconciled external effects. Recovery never clears this:
    /// no code path resets it on a below-threshold sample.
    pub(crate) fn record_effects_reconciled(&mut self) {
        self.reconciliation.effects_reconciled = true;
    }

    /// Records a quarantine intent for one exact generation with a bounded
    /// restart hold. Quarantine survives recovery; the restart owner consumes
    /// the hold instead of restarting into the same pressure.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded reference or
    /// zero time, [`PressureError::ActionNotWarranted`] without an open
    /// episode, or [`PressureError::RegistryFull`] when quarantine retention
    /// is full.
    pub(crate) fn record_quarantine(
        &mut self,
        generation_ref: &str,
        problem_pending_ref: &str,
        store_outage_retained: bool,
        now_ms: u64,
    ) -> Result<String, PressureError> {
        if !valid_id(generation_ref) {
            return Err(PressureError::InvalidField {
                field: "quarantine.generation_ref",
                reason: "must be a bounded non-blank reference",
            });
        }
        if !valid_id(problem_pending_ref) {
            return Err(PressureError::InvalidField {
                field: "quarantine.problem_pending_ref",
                reason: "must be a bounded non-blank reference",
            });
        }
        if now_ms == 0 {
            return Err(PressureError::InvalidField {
                field: "quarantine.now_ms",
                reason: "must be greater than zero",
            });
        }
        let Some(episode) = self.episode.as_ref() else {
            return Err(PressureError::ActionNotWarranted {
                action: "quarantine",
            });
        };
        if self.quarantines.len() >= MAX_QUARANTINED_GENERATIONS {
            return Err(PressureError::RegistryFull {
                registry: "quarantine",
            });
        }
        let intent = QuarantineIntent {
            generation_ref: generation_ref.to_owned(),
            episode_id: episode.episode_id.clone(),
            restart_hold_until_ms: now_ms.saturating_add(self.profile.stable_recovery_interval_ms),
            problem: ProblemIntent {
                pending_ref: problem_pending_ref.to_owned(),
                store_outage_retained,
            },
        };
        intent.validate()?;
        self.quarantines.push(intent);
        Ok(episode.episode_id.clone())
    }

    /// Builds the typed degradation disposition for paused normal admission:
    /// memory identified, work deferred, the safe next action named.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for a zero request, an unknown
    /// availability above the request, or an unbounded operation reference, or
    /// [`PressureError::InternalInvariant`] when the assembled directive
    /// fails contract validation.
    pub(crate) fn pause_degradation(
        &self,
        work: NormalWorkClass,
        requested_bytes: u64,
        available_bytes: Option<u64>,
        operation_ref: Option<&str>,
        cooldown_until_ms: u64,
    ) -> Result<I14BackpressureResponseV1, PressureError> {
        if requested_bytes == 0 {
            return Err(PressureError::InvalidField {
                field: "degradation.requested_bytes",
                reason: "must be greater than zero",
            });
        }
        let observation = match available_bytes {
            None => BottleneckObservationV1 {
                bottleneck: self.profile.bottleneck(),
                unit: CapacityUnit::MemoryBytes,
                requested_amount: requested_bytes,
                availability: BottleneckAvailability::Unknown,
                coverage_state: BottleneckCoverageState::Unknown,
            },
            Some(available) if available < requested_bytes => BottleneckObservationV1 {
                bottleneck: self.profile.bottleneck(),
                unit: CapacityUnit::MemoryBytes,
                requested_amount: requested_bytes,
                availability: BottleneckAvailability::Exhausted {
                    available_amount: available,
                },
                coverage_state: BottleneckCoverageState::Claimed,
            },
            Some(available) => BottleneckObservationV1 {
                bottleneck: self.profile.bottleneck(),
                unit: CapacityUnit::MemoryBytes,
                requested_amount: requested_bytes,
                availability: BottleneckAvailability::Available {
                    available_amount: available,
                },
                coverage_state: BottleneckCoverageState::Claimed,
            },
        };
        self.assemble_response(
            BackpressureDisposition::CapabilityDegraded,
            I14BackpressureCause::CapabilityUnavailable,
            AffectedOperationClass::Normal(work),
            observation,
            I14WorkOutcome::Deferred,
            RecoveryCommitStatus::None,
            I14RecoveryAction::AwaitCondition,
            EarliestRecoveryCondition::CapacityAvailable,
            Some(cooldown_until_ms),
            Some(I14AlternativeRoute::CanonicalReadOnly),
            I14RequiredAuthority::NoneRequired,
            HumanActionRequirement::NoneRequired,
            I14EscalationCondition::None,
            I14ResolutionState::Pending,
            I14CurrentnessState::Current,
            StatePreservationStatus::Preserved,
            operation_ref,
        )
    }

    /// Builds the typed degradation disposition for explicit unknown, denied,
    /// stale or unsupported pressure: the refusal names the unknown instead
    /// of claiming healthy capacity.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an observed state, a zero
    /// request or an unbounded operation reference, or
    /// [`PressureError::InternalInvariant`] when the assembled directive
    /// fails contract validation.
    pub(crate) fn unknown_pressure_degradation(
        &self,
        work: NormalWorkClass,
        state: ObservationState,
        requested_bytes: u64,
        operation_ref: Option<&str>,
    ) -> Result<I14BackpressureResponseV1, PressureError> {
        if state == ObservationState::Observed {
            return Err(PressureError::InvalidField {
                field: "degradation.state",
                reason: "observed pressure uses the measured disposition",
            });
        }
        if requested_bytes == 0 {
            return Err(PressureError::InvalidField {
                field: "degradation.requested_bytes",
                reason: "must be greater than zero",
            });
        }
        let (availability, currentness) = match state {
            ObservationState::Unsupported => (
                BottleneckAvailability::Unsupported,
                I14CurrentnessState::Unknown,
            ),
            ObservationState::Stale => {
                (BottleneckAvailability::Unknown, I14CurrentnessState::Stale)
            }
            ObservationState::Unknown | ObservationState::Denied | ObservationState::Observed => (
                BottleneckAvailability::Unknown,
                I14CurrentnessState::Unknown,
            ),
        };
        let coverage = if matches!(availability, BottleneckAvailability::Unsupported) {
            BottleneckCoverageState::Unsupported
        } else {
            BottleneckCoverageState::Unknown
        };
        self.assemble_response(
            BackpressureDisposition::CapabilityDegraded,
            I14BackpressureCause::CapabilityUnavailable,
            AffectedOperationClass::Normal(work),
            BottleneckObservationV1 {
                bottleneck: self.profile.bottleneck(),
                unit: CapacityUnit::MemoryBytes,
                requested_amount: requested_bytes,
                availability,
                coverage_state: coverage,
            },
            I14WorkOutcome::Deferred,
            RecoveryCommitStatus::None,
            I14RecoveryAction::AwaitCondition,
            EarliestRecoveryCondition::Unknown,
            None,
            Some(I14AlternativeRoute::CanonicalReadOnly),
            I14RequiredAuthority::Unknown,
            HumanActionRequirement::NoneRequired,
            I14EscalationCondition::None,
            I14ResolutionState::Pending,
            currentness,
            StatePreservationStatus::Unknown,
            operation_ref,
        )
    }

    /// Builds the typed degradation disposition when the protected guarantee
    /// itself is lost: unknown outcome, manual recovery, blind retry
    /// forbidden. An enum value or reserved percentage is not physically
    /// available memory, so this names the existing manual-recovery path.
    ///
    /// # Errors
    /// Returns [`PressureError::InvalidField`] for an unbounded operation
    /// reference, or [`PressureError::InternalInvariant`] when the assembled
    /// directive fails contract validation.
    pub(crate) fn manual_recovery_degradation(
        &self,
        operation_ref: Option<&str>,
    ) -> Result<I14BackpressureResponseV1, PressureError> {
        let operation = match operation_ref {
            Some(reference) => {
                Some(
                    OperationId::new(reference).map_err(|_| PressureError::InvalidField {
                        field: "degradation.operation_ref",
                        reason: "must be a bounded non-blank reference",
                    })?,
                )
            }
            None => None,
        };
        let response = I14BackpressureResponseV1 {
            contract_version: I14_BACKPRESSURE_RESPONSE_VERSION,
            disposition: BackpressureDisposition::CapabilityDegraded,
            directive: I14RecoveryDirectiveV1 {
                cause: I14BackpressureCause::CapabilityUnavailable,
                affected_operation_class: AffectedOperationClass::Emergency(
                    EmergencyOperationClass::EnterManualRecovery,
                ),
                bottlenecks: vec![BottleneckObservationV1 {
                    bottleneck: self.profile.bottleneck(),
                    unit: CapacityUnit::MemoryBytes,
                    requested_amount: self.profile.admission_stop_bytes(),
                    availability: BottleneckAvailability::Unknown,
                    coverage_state: BottleneckCoverageState::Unknown,
                }],
                work_outcome: I14WorkOutcome::Unknown,
                commit_status: RecoveryCommitStatus::Unknown,
                state_preservation: StatePreservationStatus::Unknown,
                operation_id: operation,
                preserve_operation_id: operation_ref.is_some(),
                stage_receipt: None,
                rollback_receipt: None,
                retry_strategy: I14RecoveryAction::ManualRecovery,
                earliest_permitted_condition: EarliestRecoveryCondition::ManualRecoveryComplete,
                earliest_permitted_unix_millis: None,
                actions_temporarily_forbidden: vec![
                    I14ForbiddenAction::BlindRetryAfterPossibleEffect,
                ],
                safe_fallback: Some(I14AlternativeRoute::HumanRecoverySurface),
                required_authority: I14RequiredAuthority::HumanOrPlatformRecovery,
                human_action_required: HumanActionRequirement::HumanOrPlatformRecovery,
                evidence_refs: Vec::new(),
                evidence_coverage: EvidenceCoverageState::Unknown,
                escalation_condition: I14EscalationCondition::ManualPlatformRecovery,
                resolution_state: I14ResolutionState::ManualRecoveryRequired,
                currentness: I14CurrentnessState::Unknown,
                profile_revision: self.directive_profile_revision()?,
                state_fence: None,
                authority_epoch: None,
            },
        };
        response
            .validate()
            .map_err(|_| PressureError::InternalInvariant {
                field: "degradation.directive",
            })?;
        Ok(response)
    }

    /// Returns the current episode level, or `Normal` when no episode is open.
    fn current_level(&self) -> PressureLevel {
        self.episode
            .as_ref()
            .map_or(PressureLevel::Normal, |episode| episode.level)
    }

    /// Opens or escalates the episode for classified pressure. Recovery never
    /// happens here: only [`Self::track_recovery`] closes an episode.
    fn track_episode(&mut self, classified: PressureLevel, now_ms: u64) {
        if classified == PressureLevel::Normal {
            return;
        }
        if let Some(episode) = self.episode.as_mut() {
            if classified > episode.level {
                episode.level = classified;
            }
            episode.last_update_ms = now_ms;
        } else {
            let episode_id = format!("{}:pressure:{now_ms}", self.profile.profile_id());
            self.episode = Some(PressureEpisode {
                episode_id,
                level: classified,
                started_at_ms: now_ms,
                last_update_ms: now_ms,
                actions: Vec::new(),
            });
        }
    }

    /// Closes the episode only after the stable interval below the recovery
    /// band with the required protected permits visible. Quarantine, unknown
    /// effects and reservations are untouched: this only ends the episode and
    /// resets the band timer.
    fn track_recovery(&mut self, observed: u64, reserve: ReserveSnapshot, now_ms: u64) {
        if self.episode.is_none() {
            self.below_band_since_ms = None;
            return;
        }
        if observed < self.profile.recovery_ceiling() {
            let since = *self.below_band_since_ms.get_or_insert(now_ms);
            let stable = now_ms.saturating_sub(since) >= self.profile.stable_recovery_interval_ms;
            let reserve_ok = reserve.protected_permits >= self.profile.protected_permits_required;
            if stable && reserve_ok {
                self.episode = None;
                self.below_band_since_ms = None;
            }
        } else {
            self.below_band_since_ms = None;
        }
    }

    /// Records the level-stable action identity once per episode. Repeats
    /// reuse the record; the profile backstop bounds the log instead of
    /// launching duplicate actions.
    fn record_level_action(&mut self, action_id: &str, level: PressureLevel, deadline_ms: u64) {
        let Some(episode) = self.episode.as_mut() else {
            return;
        };
        if episode
            .actions
            .iter()
            .any(|action| action.action_id == action_id)
        {
            return;
        }
        if episode.actions.len() >= self.profile.max_actions_per_episode as usize {
            return;
        }
        let kind = match level {
            PressureLevel::Normal | PressureLevel::Warning => PressureActionKind::EmitDegradation,
            PressureLevel::AdmissionStop => PressureActionKind::PauseAdmission,
            PressureLevel::Checkpoint => PressureActionKind::RequestCheckpoint,
            PressureLevel::Containment => PressureActionKind::RequestContainment,
        };
        episode.actions.push(PressureActionRecord {
            action_id: action_id.to_owned(),
            kind,
            state: PressureActionState::Requested,
            deadline_ms,
        });
    }

    /// Marks the latest open action of one kind reconciled.
    fn reconcile_action(&mut self, kind: PressureActionKind) {
        let Some(episode) = self.episode.as_mut() else {
            return;
        };
        if let Some(action) =
            episode.actions.iter_mut().rev().find(|action| {
                action.kind == kind && action.state != PressureActionState::Reconciled
            })
        {
            action.state = PressureActionState::Reconciled;
        }
    }

    /// Returns the directive profile revision as a validated artifact identity.
    fn directive_profile_revision(&self) -> Result<ArtifactId, PressureError> {
        ArtifactId::new(self.profile.revision()).map_err(|_| PressureError::InternalInvariant {
            field: "profile.revision",
        })
    }

    /// Assembles, validates and returns one typed degradation response. The
    /// response fails closed instead of emitting an invalid directive.
    #[allow(
        clippy::too_many_arguments,
        reason = "the I14 directive joins one explicit field per contract dimension; grouping would hide a dimension"
    )]
    fn assemble_response(
        &self,
        disposition: BackpressureDisposition,
        cause: I14BackpressureCause,
        affected: AffectedOperationClass,
        bottleneck: BottleneckObservationV1,
        work_outcome: I14WorkOutcome,
        commit_status: RecoveryCommitStatus,
        retry_strategy: I14RecoveryAction,
        condition: EarliestRecoveryCondition,
        earliest_ms: Option<u64>,
        fallback: Option<I14AlternativeRoute>,
        authority: I14RequiredAuthority,
        human: HumanActionRequirement,
        escalation: I14EscalationCondition,
        resolution: I14ResolutionState,
        currentness: I14CurrentnessState,
        preservation: StatePreservationStatus,
        operation_ref: Option<&str>,
    ) -> Result<I14BackpressureResponseV1, PressureError> {
        let operation = match operation_ref {
            Some(reference) => {
                Some(
                    OperationId::new(reference).map_err(|_| PressureError::InvalidField {
                        field: "degradation.operation_ref",
                        reason: "must be a bounded non-blank reference",
                    })?,
                )
            }
            None => None,
        };
        let response = I14BackpressureResponseV1 {
            contract_version: I14_BACKPRESSURE_RESPONSE_VERSION,
            disposition,
            directive: I14RecoveryDirectiveV1 {
                cause,
                affected_operation_class: affected,
                bottlenecks: vec![bottleneck],
                work_outcome,
                commit_status,
                state_preservation: preservation,
                operation_id: operation,
                preserve_operation_id: operation_ref.is_some(),
                stage_receipt: None,
                rollback_receipt: None,
                retry_strategy,
                earliest_permitted_condition: condition,
                earliest_permitted_unix_millis: earliest_ms,
                actions_temporarily_forbidden: Vec::new(),
                safe_fallback: fallback,
                required_authority: authority,
                human_action_required: human,
                evidence_refs: Vec::new(),
                evidence_coverage: EvidenceCoverageState::Unavailable,
                escalation_condition: escalation,
                resolution_state: resolution,
                currentness,
                profile_revision: self.directive_profile_revision()?,
                state_fence: None,
                authority_epoch: None,
            },
        };
        response
            .validate()
            .map_err(|_| PressureError::InternalInvariant {
                field: "degradation.directive",
            })?;
        Ok(response)
    }
}
