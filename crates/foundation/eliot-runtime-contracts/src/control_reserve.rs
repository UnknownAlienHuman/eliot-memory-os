//! Closed control-reserve capacity vocabulary owned by runtime contracts.
//!
//! This is descriptive contract data only. Physical acquisition, enforcement,
//! and capacity observation remain with each bottleneck's runtime owner.

use std::num::NonZeroU64;

use eliot_contracts::{EpochId, ResourceGeneration};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::RuntimeContractError;

/// The non-borrowable partition selected for a capacity request.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapacityClass {
    /// Ordinary workload admission.
    NormalWorkload,
    /// Reserved control and recovery admission.
    ProtectedControl,
    /// Preallocated last-resort loss-reporting/recovery entry.
    EmergencyLastResort,
}

impl CapacityClass {
    /// Returns the exact frozen contract identifier.
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::NormalWorkload => "NORMAL_WORKLOAD",
            Self::ProtectedControl => "PROTECTED_CONTROL",
            Self::EmergencyLastResort => "EMERGENCY_LAST_RESORT",
        }
    }
}

/// Closed set of ordinary workload classes.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NormalWorkClass {
    /// Interactive and named-read admission.
    Interactive,
    /// Verification work.
    Verification,
    /// Canonical Store writes.
    CanonicalWrite,
    /// Ordinary background work.
    NormalBackground,
    /// Model-job admission.
    ModelJob,
    /// Swarm and agent admission.
    Swarm,
    /// Reporting work.
    Reporting,
    /// Maintenance work.
    Maintenance,
}

impl NormalWorkClass {
    /// Returns the exact frozen contract identifier.
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::Interactive => "INTERACTIVE",
            Self::Verification => "VERIFICATION",
            Self::CanonicalWrite => "CANONICAL_WRITE",
            Self::NormalBackground => "NORMAL_BACKGROUND",
            Self::ModelJob => "MODEL_JOB",
            Self::Swarm => "SWARM",
            Self::Reporting => "REPORTING",
            Self::Maintenance => "MAINTENANCE",
        }
    }
}

/// Closed set of operations eligible for protected control capacity.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlOperationClass {
    /// Operation cancellation.
    CancelOperation,
    /// Fence a stale owner.
    FenceStaleOwner,
    /// Revoke authority.
    RevokeAuthority,
    /// Health/readiness control.
    HealthReadinessControl,
    /// Publish critical telemetry.
    CriticalTelemetry,
    /// Transition Critical Attention.
    CriticalAttentionTransition,
    /// Transition Problem State.
    ProblemTransition,
    /// Transition Incident State.
    IncidentTransition,
    /// Transition persistent notification/inbox state.
    PersistentNotificationTransition,
    /// Safely shut down.
    SafeShutdown,
    /// Drain an owner.
    Drain,
    /// Enter recovery.
    Recovery,
    /// Contain a local failure.
    Containment,
    /// Reconcile an exact unknown outcome.
    UnknownOutcomeReconciliation,
}

impl ControlOperationClass {
    /// Returns the exact frozen contract identifier.
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::CancelOperation => "CANCEL_OPERATION",
            Self::FenceStaleOwner => "FENCE_STALE_OWNER",
            Self::RevokeAuthority => "REVOKE_AUTHORITY",
            Self::HealthReadinessControl => "HEALTH_READINESS_CONTROL",
            Self::CriticalTelemetry => "CRITICAL_TELEMETRY",
            Self::CriticalAttentionTransition => "CRITICAL_ATTENTION_TRANSITION",
            Self::ProblemTransition => "PROBLEM_TRANSITION",
            Self::IncidentTransition => "INCIDENT_TRANSITION",
            Self::PersistentNotificationTransition => "PERSISTENT_NOTIFICATION_TRANSITION",
            Self::SafeShutdown => "SAFE_SHUTDOWN",
            Self::Drain => "DRAIN",
            Self::Recovery => "RECOVERY",
            Self::Containment => "CONTAINMENT",
            Self::UnknownOutcomeReconciliation => "UNKNOWN_OUTCOME_RECONCILIATION",
        }
    }
}

/// Closed set of emergency last-resort operations.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EmergencyOperationClass {
    /// Record a reserve-exhaustion coverage gap.
    ReserveExhaustionGapRecord,
    /// Record loss of the control guarantee.
    ControlGuaranteeLostRecord,
    /// Enter manual/platform recovery.
    EnterManualRecovery,
}

impl EmergencyOperationClass {
    /// Returns the exact frozen contract identifier.
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::ReserveExhaustionGapRecord => "RESERVE_EXHAUSTION_GAP_RECORD",
            Self::ControlGuaranteeLostRecord => "CONTROL_GUARANTEE_LOST_RECORD",
            Self::EnterManualRecovery => "ENTER_MANUAL_RECOVERY",
        }
    }
}

/// Exact bottlenecks in the frozen I14 denominator.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapacityBottleneck {
    /// Kernel control channel.
    KernelControlChannel,
    /// Kernel runnable control slots.
    KernelRunnableControlSlots,
    /// ORS transaction slots.
    OrsTransactionSlots,
    /// ORS durable queue bytes.
    OrsDurableQueueBytes,
    /// Store connection slots.
    StoreConnectionSlots,
    /// Store transaction slots.
    StoreTransactionSlots,
    /// Store pending-write memory.
    StorePendingWriteMemory,
    /// Process launch slots.
    ProcessLaunchSlots,
    /// Process cancellation/termination operations.
    ProcessCancellationTermination,
    /// Persistent notification/inbox items.
    NotificationPersistentInbox,
    /// CPU control-task slots.
    CpuControlTaskSlots,
    /// Protected memory bytes.
    ProtectedMemoryBytes,
    /// Pipe/message bytes.
    PipeMessageBytes,
    /// File descriptor/handle slots.
    FileDescriptorHandleSlots,
    /// Disk queue/write slots.
    DiskQueueWriteCapacity,
}

impl CapacityBottleneck {
    /// Returns the exact frozen contract identifier.
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::KernelControlChannel => "KERNEL_CONTROL_CHANNEL",
            Self::KernelRunnableControlSlots => "KERNEL_RUNNABLE_CONTROL_SLOTS",
            Self::OrsTransactionSlots => "ORS_TRANSACTION_SLOTS",
            Self::OrsDurableQueueBytes => "ORS_DURABLE_QUEUE_BYTES",
            Self::StoreConnectionSlots => "STORE_CONNECTION_SLOTS",
            Self::StoreTransactionSlots => "STORE_TRANSACTION_SLOTS",
            Self::StorePendingWriteMemory => "STORE_PENDING_WRITE_MEMORY",
            Self::ProcessLaunchSlots => "PROCESS_LAUNCH_SLOTS",
            Self::ProcessCancellationTermination => "PROCESS_CANCELLATION_TERMINATION",
            Self::NotificationPersistentInbox => "NOTIFICATION_PERSISTENT_INBOX",
            Self::CpuControlTaskSlots => "CPU_CONTROL_TASK_SLOTS",
            Self::ProtectedMemoryBytes => "PROTECTED_MEMORY_BYTES",
            Self::PipeMessageBytes => "PIPE_MESSAGE_BYTES",
            Self::FileDescriptorHandleSlots => "FILE_DESCRIPTOR_HANDLE_SLOTS",
            Self::DiskQueueWriteCapacity => "DISK_QUEUE_WRITE_CAPACITY",
        }
    }

    /// Returns the only unit permitted for this bottleneck.
    #[must_use]
    pub const fn unit(self) -> CapacityUnit {
        match self {
            Self::KernelControlChannel | Self::NotificationPersistentInbox => CapacityUnit::Items,
            Self::KernelRunnableControlSlots => CapacityUnit::RunnableSlots,
            Self::OrsTransactionSlots | Self::StoreTransactionSlots => CapacityUnit::Transactions,
            Self::OrsDurableQueueBytes | Self::PipeMessageBytes => CapacityUnit::Bytes,
            Self::StoreConnectionSlots => CapacityUnit::Connections,
            Self::StorePendingWriteMemory | Self::ProtectedMemoryBytes => CapacityUnit::MemoryBytes,
            Self::ProcessLaunchSlots => CapacityUnit::ProcessSlots,
            Self::ProcessCancellationTermination => CapacityUnit::ConcurrentOperations,
            Self::CpuControlTaskSlots => CapacityUnit::CpuTaskSlots,
            Self::FileDescriptorHandleSlots => CapacityUnit::Handles,
            Self::DiskQueueWriteCapacity => CapacityUnit::DiskQueueSlots,
        }
    }
}

/// Exact units used by I14 capacity owners.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapacityUnit {
    /// Discrete items.
    Items,
    /// Bytes.
    Bytes,
    /// Concurrent operations.
    ConcurrentOperations,
    /// Runnable task slots.
    RunnableSlots,
    /// Store connections.
    Connections,
    /// Transactions.
    Transactions,
    /// Process slots.
    ProcessSlots,
    /// CPU task slots.
    CpuTaskSlots,
    /// Memory bytes.
    MemoryBytes,
    /// File descriptors or handles.
    Handles,
    /// Disk queue slots.
    DiskQueueSlots,
}

impl CapacityUnit {
    /// Returns the exact frozen contract identifier.
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::Items => "ITEMS",
            Self::Bytes => "BYTES",
            Self::ConcurrentOperations => "CONCURRENT_OPERATIONS",
            Self::RunnableSlots => "RUNNABLE_SLOTS",
            Self::Connections => "CONNECTIONS",
            Self::Transactions => "TRANSACTIONS",
            Self::ProcessSlots => "PROCESS_SLOTS",
            Self::CpuTaskSlots => "CPU_TASK_SLOTS",
            Self::MemoryBytes => "MEMORY_BYTES",
            Self::Handles => "HANDLES",
            Self::DiskQueueSlots => "DISK_QUEUE_SLOTS",
        }
    }
}

/// Closed set of enforceable partition mechanisms for a reserved partition.
///
/// `PRIORITY_ONLY` is deliberately not a value: priority ordering cannot
/// reserve capacity.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapacityEnforcement {
    /// Physically separate capacity normal work cannot acquire.
    PhysicalPartition,
    /// Configurationally separate capacity reserved before normal work.
    ConfigurationPartition,
    /// Platform-preallocated capacity outside normal and protected accounting.
    PlatformPreallocation,
}

impl CapacityEnforcement {
    /// Returns the exact frozen contract identifier.
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::PhysicalPartition => "PHYSICAL_PARTITION",
            Self::ConfigurationPartition => "CONFIGURATION_PARTITION",
            Self::PlatformPreallocation => "PLATFORM_PREALLOCATION",
        }
    }
}

/// Coverage status for one exact bottleneck row.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BottleneckCoverageState {
    /// The owner claims the declared capacity guarantee.
    Claimed,
    /// The owner does not provide this guarantee.
    Unsupported,
    /// Coverage has not been established.
    Unknown,
}

impl BottleneckCoverageState {
    /// Returns the exact frozen contract identifier.
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::Claimed => "CLAIMED",
            Self::Unsupported => "UNSUPPORTED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// One positive capacity amount expressed in the exact unit of its owner.
///
/// The frozen contract pins the quantity to a [`NonZeroU64`], so a positive
/// amount is a type property rather than a runtime check; the unit still has to
/// equal the unit declared by the owning bottleneck contract.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityLimit {
    /// Unit declared by the owning bottleneck contract.
    pub unit: CapacityUnit,
    /// Positive amount in `unit`; zero capacity is not representable.
    pub quantity: NonZeroU64,
}

/// The frozen owner map row: one bottleneck, one unit, one runtime owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BottleneckOwnerBinding {
    /// Exact bottleneck from the frozen fifteen-value denominator.
    pub bottleneck: CapacityBottleneck,
    /// Exact unit declared for this bottleneck.
    pub unit: CapacityUnit,
    /// Runtime owner string, verbatim from the frozen contract row.
    pub owner: &'static str,
}

/// The frozen owner map: exactly one binding for every [`CapacityBottleneck`].
///
/// The fifteen entries are the `[[bottleneck_contract]]` rows of
/// `control-reserve.contract.toml`, in contract order. This map is the only
/// enumeration of the denominator: it records owner and unit per dimension and
/// claims no physical total, owner generation, enforcement, proof, evidence or
/// invalidation value for any dimension.
#[must_use]
pub const fn frozen_bottleneck_owner_map() -> [BottleneckOwnerBinding; 15] {
    [
        BottleneckOwnerBinding {
            bottleneck: CapacityBottleneck::KernelControlChannel,
            unit: CapacityUnit::Items,
            owner: "Kernel front-door/control-channel owner",
        },
        BottleneckOwnerBinding {
            bottleneck: CapacityBottleneck::KernelRunnableControlSlots,
            unit: CapacityUnit::RunnableSlots,
            owner: "Kernel runtime/control scheduler owner",
        },
        BottleneckOwnerBinding {
            bottleneck: CapacityBottleneck::OrsTransactionSlots,
            unit: CapacityUnit::Transactions,
            owner: "Kernel ORS owner",
        },
        BottleneckOwnerBinding {
            bottleneck: CapacityBottleneck::OrsDurableQueueBytes,
            unit: CapacityUnit::Bytes,
            owner: "Kernel ORS owner",
        },
        BottleneckOwnerBinding {
            bottleneck: CapacityBottleneck::StoreConnectionSlots,
            unit: CapacityUnit::Connections,
            owner: "Store bridge generation",
        },
        BottleneckOwnerBinding {
            bottleneck: CapacityBottleneck::StoreTransactionSlots,
            unit: CapacityUnit::Transactions,
            owner: "Store bridge generation",
        },
        BottleneckOwnerBinding {
            bottleneck: CapacityBottleneck::StorePendingWriteMemory,
            unit: CapacityUnit::MemoryBytes,
            owner: "Store bridge generation",
        },
        BottleneckOwnerBinding {
            bottleneck: CapacityBottleneck::ProcessLaunchSlots,
            unit: CapacityUnit::ProcessSlots,
            owner: "Host/Kernel process-tree owner",
        },
        BottleneckOwnerBinding {
            bottleneck: CapacityBottleneck::ProcessCancellationTermination,
            unit: CapacityUnit::ConcurrentOperations,
            owner: "Host/Kernel process-tree owner",
        },
        BottleneckOwnerBinding {
            bottleneck: CapacityBottleneck::NotificationPersistentInbox,
            unit: CapacityUnit::Items,
            owner: "Governor notification/inbox owner with protected delivery path",
        },
        BottleneckOwnerBinding {
            bottleneck: CapacityBottleneck::CpuControlTaskSlots,
            unit: CapacityUnit::CpuTaskSlots,
            owner: "Kernel runtime/control scheduler owner",
        },
        BottleneckOwnerBinding {
            bottleneck: CapacityBottleneck::ProtectedMemoryBytes,
            unit: CapacityUnit::MemoryBytes,
            owner: "Kernel/runtime memory-budget owner",
        },
        BottleneckOwnerBinding {
            bottleneck: CapacityBottleneck::PipeMessageBytes,
            unit: CapacityUnit::Bytes,
            owner: "IPC/control-channel owner",
        },
        BottleneckOwnerBinding {
            bottleneck: CapacityBottleneck::FileDescriptorHandleSlots,
            unit: CapacityUnit::Handles,
            owner: "platform/process/IPC owner",
        },
        BottleneckOwnerBinding {
            bottleneck: CapacityBottleneck::DiskQueueWriteCapacity,
            unit: CapacityUnit::DiskQueueSlots,
            owner: "Host/ORS/store/spool owner for the declared path",
        },
    ]
}

/// One owner-produced row of the frozen capacity denominator.
///
/// The three borrow flags of the frozen contract are not fields: that contract
/// pins `normal_may_borrow_protected`, `normal_may_borrow_emergency` and
/// `protected_may_borrow_emergency` at the literal value `false`, so they are
/// exposed as the fixed constants [`Self::NORMAL_MAY_BORROW_PROTECTED`],
/// [`Self::NORMAL_MAY_BORROW_EMERGENCY`] and
/// [`Self::PROTECTED_MAY_BORROW_EMERGENCY`] instead of settable parameters.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BottleneckCapacityProfile {
    /// Exact bottleneck dimension.
    pub bottleneck: CapacityBottleneck,
    /// Claimed, unsupported or unknown coverage of this dimension.
    pub coverage_state: BottleneckCoverageState,
    /// Runtime owner reference for this dimension.
    pub owner_ref: String,
    /// Owner generation/revision reference for this dimension.
    pub owner_generation_ref: String,
    /// Unit of this row; quantities from other units never join it.
    pub unit: CapacityUnit,
    /// Total physical capacity of this dimension, when it is established.
    pub physical_total_limit: Option<CapacityLimit>,
    /// Whether ordinary workload is admitted at this dimension.
    pub normal_work_applicable: bool,
    /// Non-borrowable normal workload partition, when applicable.
    pub normal_limit: Option<CapacityLimit>,
    /// Non-borrowable protected control/recovery partition.
    pub protected_limit: Option<CapacityLimit>,
    /// Preallocated emergency last-resort partition, outside normal and
    /// protected accounting.
    pub emergency_limit: Option<CapacityLimit>,
    /// Enforceable partition mechanism; absent means none is claimed.
    pub enforcement: Option<CapacityEnforcement>,
    /// Independent proof profile reference produced by the owner.
    pub proof_profile_ref: String,
    /// Current owner evidence references supporting the row.
    pub evidence_refs: Vec<String>,
    /// Exact invalidation set of this row.
    pub invalidation_set: Vec<String>,
}

impl BottleneckCapacityProfile {
    /// The frozen contract pins this normal borrow flag at `false`.
    pub const NORMAL_MAY_BORROW_PROTECTED: bool = false;
    /// The frozen contract pins this normal borrow flag at `false`.
    pub const NORMAL_MAY_BORROW_EMERGENCY: bool = false;
    /// The frozen contract pins this protected borrow flag at `false`.
    pub const PROTECTED_MAY_BORROW_EMERGENCY: bool = false;

    /// Validates one row against the closed contract invariants.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContractError::InvalidField`] naming the first violated
    /// invariant of `[types.BottleneckCapacityProfile]`.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        self.validate_unit()?;
        self.validate_claim()?;
        self.validate_unclaimed_capacity()?;
        self.validate_partition_accounting()?;
        validate_canonical_refs("evidence_refs", &self.evidence_refs)?;
        validate_canonical_refs("invalidation_set", &self.invalidation_set)
    }

    fn validate_unit(&self) -> Result<(), RuntimeContractError> {
        if self.unit != self.bottleneck.unit() {
            return Err(invalid(
                "unit",
                "UNIT_MISMATCH: a bottleneck profile uses exactly its declared unit",
            ));
        }
        for (field, limit) in self.declared_limits() {
            if limit.unit != self.unit {
                return Err(invalid(
                    field,
                    "UNIT_MISMATCH: all present limits use the exact row unit",
                ));
            }
        }
        Ok(())
    }

    fn validate_claim(&self) -> Result<(), RuntimeContractError> {
        if self.coverage_state != BottleneckCoverageState::Claimed {
            return Ok(());
        }
        if self.owner_ref.trim().is_empty() || self.owner_generation_ref.trim().is_empty() {
            return Err(invalid(
                "owner_ref",
                "MISSING_CAPACITY_OWNER: a claimed row names one runtime owner and one owner generation",
            ));
        }
        if self.physical_total_limit.is_none() {
            return Err(invalid(
                "physical_total_limit",
                "a claimed row requires the physical total of this dimension",
            ));
        }
        if self.protected_limit.is_none() {
            return Err(invalid(
                "protected_limit",
                "MISSING_PROTECTED_PARTITION: a claimed row requires a protected partition",
            ));
        }
        if self.enforcement.is_none() {
            return Err(invalid(
                "enforcement",
                "MISSING_ENFORCEMENT: a claimed row requires an enforceable partition mechanism",
            ));
        }
        if self.proof_profile_ref.trim().is_empty() {
            return Err(invalid(
                "proof_profile_ref",
                "MISSING_PROOF_PROFILE: a claimed row requires an independent proof profile",
            ));
        }
        if self.evidence_refs.is_empty() {
            return Err(invalid(
                "evidence_refs",
                "MISSING_EVIDENCE: a claimed row requires current owner evidence",
            ));
        }
        if self.invalidation_set.is_empty() {
            return Err(invalid(
                "invalidation_set",
                "MISSING_INVALIDATION_SET: a claimed row requires an invalidation set",
            ));
        }
        if self.normal_work_applicable && self.normal_limit.is_none() {
            return Err(invalid(
                "normal_limit",
                "MISSING_NORMAL_PARTITION: a claimed row with normal work requires a normal partition",
            ));
        }
        Ok(())
    }

    fn validate_unclaimed_capacity(&self) -> Result<(), RuntimeContractError> {
        if self.coverage_state == BottleneckCoverageState::Claimed {
            return Ok(());
        }
        if self.physical_total_limit.is_some()
            || self.normal_limit.is_some()
            || self.protected_limit.is_some()
            || self.emergency_limit.is_some()
            || self.enforcement.is_some()
        {
            return Err(invalid(
                "coverage_state",
                "UNKNOWN_OR_UNSUPPORTED_BOTTLENECK: an unsupported or unknown row carries no capacity or enforcement claim",
            ));
        }
        Ok(())
    }

    fn validate_partition_accounting(&self) -> Result<(), RuntimeContractError> {
        let Some(physical_total) = &self.physical_total_limit else {
            return Ok(());
        };
        let mut partitioned = 0_u64;
        for (_, limit) in self.declared_limits() {
            partitioned = partitioned
                .checked_add(limit.quantity.get())
                .ok_or_else(|| {
                    invalid(
                        "physical_total_limit",
                        "CAPACITY_SUM_OVERFLOW: the disjoint partition sum overflows",
                    )
                })?;
        }
        if partitioned > physical_total.quantity.get() {
            return Err(invalid(
                "physical_total_limit",
                "PARTITIONS_EXCEED_PHYSICAL_TOTAL: the physical total is at least the sum of all present disjoint partitions",
            ));
        }
        Ok(())
    }

    /// Returns the present disjoint partitions, emergency last, so a physical
    /// total always bounds them.
    fn declared_limits(&self) -> impl Iterator<Item = (&'static str, &CapacityLimit)> {
        [
            ("normal_limit", self.normal_limit.as_ref()),
            ("protected_limit", self.protected_limit.as_ref()),
            ("emergency_limit", self.emergency_limit.as_ref()),
        ]
        .into_iter()
        .filter_map(|(field, limit)| Some((field, limit?)))
    }
}

/// The complete current capacity vector: one row for every bottleneck.
///
/// The profile describes and validates the capacity vector only. It owns no
/// queue, semaphore, memory, permit or health state, and it neither compiles a
/// profile nor observes owner capacity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlReserveProfile {
    /// Stable profile identity.
    pub profile_id: String,
    /// Immutable revision of this profile.
    pub profile_revision: String,
    /// Exact product identity this profile describes.
    pub product_identity_ref: String,
    /// Source, build and runtime generation references this profile binds.
    pub source_build_and_runtime_generation_refs: Vec<String>,
    /// Exact configuration snapshot the rows were read from.
    pub config_snapshot_ref: String,
    /// Canonical typed Authority Epoch every row is bound to.
    pub authority_epoch_ref: EpochId,
    /// Compilation time in Unix milliseconds.
    pub compiled_at_ms: u64,
    /// Exactly one row per bottleneck, in the frozen contract order.
    pub bottleneck_rows: Vec<BottleneckCapacityProfile>,
    /// Guarantees lowered because a row is unsupported or unknown.
    pub unsupported_or_unknown_guarantees: Vec<String>,
    /// Current profile-level evidence references.
    pub profile_evidence_refs: Vec<String>,
    /// Exact profile-level invalidation set.
    pub invalidation_set: Vec<String>,
}

impl ControlReserveProfile {
    /// Validates the complete denominator and every row it contains.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContractError::InvalidField`] naming the first violated
    /// invariant of `[types.ControlReserveProfile]`.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        self.validate_denominator()?;
        validate_canonical_refs(
            "source_build_and_runtime_generation_refs",
            &self.source_build_and_runtime_generation_refs,
        )?;
        validate_canonical_refs(
            "unsupported_or_unknown_guarantees",
            &self.unsupported_or_unknown_guarantees,
        )?;
        validate_canonical_refs("profile_evidence_refs", &self.profile_evidence_refs)?;
        validate_canonical_refs("invalidation_set", &self.invalidation_set)
    }

    fn validate_denominator(&self) -> Result<(), RuntimeContractError> {
        let owner_map = frozen_bottleneck_owner_map();
        for (index, row) in self.bottleneck_rows.iter().enumerate() {
            if self.bottleneck_rows[..index]
                .iter()
                .any(|earlier| earlier.bottleneck == row.bottleneck)
            {
                return Err(invalid(
                    "bottleneck_rows",
                    "DUPLICATE_BOTTLENECK: a profile contains exactly one row for every value",
                ));
            }
            row.validate()?;
        }
        if self.bottleneck_rows.len() != owner_map.len()
            || owner_map.iter().any(|bound| {
                !self
                    .bottleneck_rows
                    .iter()
                    .any(|row| row.bottleneck == bound.bottleneck)
            })
        {
            return Err(invalid(
                "bottleneck_rows",
                "MISSING_BOTTLENECK: a profile contains the exact complete CapacityBottleneck denominator",
            ));
        }
        for (index, bound) in owner_map.iter().enumerate() {
            if self.bottleneck_rows[index].bottleneck != bound.bottleneck {
                return Err(invalid(
                    "bottleneck_rows",
                    "NONCANONICAL_PROFILE: bottleneck rows follow the frozen contract order",
                ));
            }
        }
        Ok(())
    }
}

/// Closed tag selecting the only admissible capacity class for one request.
///
/// The tag is the class: a normal Store write ([`NormalWorkClass::CanonicalWrite`]),
/// named read ([`NormalWorkClass::Interactive`]), verification, background, model,
/// swarm/agent ([`NormalWorkClass::Swarm`]), reporting or maintenance task can only
/// name [`NormalWorkClass`], which admits exactly [`CapacityClass::NormalWorkload`].
/// There is no independent class or priority override, so protected or emergency
/// capacity is unreachable by relabelling (issue #1679, A5).
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestedOperationClass {
    /// Ordinary workload operation.
    Normal(NormalWorkClass),
    /// Protected control/recovery operation.
    Protected(ControlOperationClass),
    /// Emergency last-resort operation.
    Emergency(EmergencyOperationClass),
}

impl RequestedOperationClass {
    /// Returns the only capacity class this operation may draw from.
    #[must_use]
    pub const fn capacity_class(self) -> CapacityClass {
        match self {
            Self::Normal(_) => CapacityClass::NormalWorkload,
            Self::Protected(_) => CapacityClass::ProtectedControl,
            Self::Emergency(_) => CapacityClass::EmergencyLastResort,
        }
    }

    /// Returns the exact frozen contract identifier of the inner class.
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::Normal(class) => class.as_contract_str(),
            Self::Protected(class) => class.as_contract_str(),
            Self::Emergency(class) => class.as_contract_str(),
        }
    }
}

/// One typed capacity request: the exact bottleneck, unit and amount under
/// exactly one operation class (frozen `[types.CapacityRequest]`).
///
/// The [`RequestedOperationClass`] tag determines the only admissible
/// [`CapacityClass`]; the caller cannot provide an independent class override.
/// The request carries no authority by itself: the bottleneck owner validates
/// it against the current row, acquires atomically under its own
/// implementation, and returns the owner-produced [`CapacityPermitBinding`].
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityRequest {
    /// Closed operation tag; the only admissible capacity class derives from it.
    pub operation: RequestedOperationClass,
    /// Operation identity the permit would be bound to.
    pub operation_id: String,
    /// Exact bottleneck dimension requested.
    pub requested_bottleneck: CapacityBottleneck,
    /// Exact amount in the bottleneck unit ([`CapacityBottleneck::unit`]).
    pub requested_limit: CapacityLimit,
    /// Owner requesting admission.
    pub requesting_owner_ref: String,
    /// Requester generation at request time.
    pub requesting_generation_ref: ResourceGeneration,
    /// Authority Epoch the request is bound to.
    pub authority_epoch_ref: EpochId,
    /// Profile identity the request was compiled against.
    pub profile_id: String,
    /// Profile revision the request was compiled against.
    pub profile_revision: String,
    /// Caller deadline in Unix milliseconds; recorded, never authority.
    pub deadline_ms: u64,
}

impl CapacityRequest {
    /// Returns the only capacity class this request may draw from.
    #[must_use]
    pub const fn capacity_class(&self) -> CapacityClass {
        self.operation.capacity_class()
    }

    /// Validates request legality without granting authority.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContractError::InvalidField`] naming the first violated
    /// invariant of `[types.CapacityRequest]`.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        if self.operation_id.trim().is_empty() {
            return Err(invalid(
                "operation_id",
                "MISSING_OPERATION_IDENTITY: a request names one operation identity",
            ));
        }
        if self.requesting_owner_ref.trim().is_empty() {
            return Err(invalid(
                "requesting_owner_ref",
                "MISSING_REQUESTER: a request names one requesting owner",
            ));
        }
        if self.profile_id.trim().is_empty() || self.profile_revision.trim().is_empty() {
            return Err(invalid(
                "profile_revision",
                "STALE_PROFILE: a request binds one profile identity and revision",
            ));
        }
        if self.requested_limit.unit != self.requested_bottleneck.unit() {
            return Err(invalid(
                "requested_limit",
                "UNIT_MISMATCH: a request uses exactly the bottleneck unit",
            ));
        }
        Ok(())
    }
}

/// One owner-issued non-clone permit binding (frozen `[types.CapacityPermitBinding]`).
///
/// The binding exactly matches one validated [`CapacityRequest`] and one current
/// bottleneck row: same operation tag and identity, same capacity class, same
/// bottleneck with the same unit and granted amount, same owner and requester
/// generations, same Authority Epoch and profile revision. Any changed content
/// fails closed instead of replaying (issue #1679, A7). The binding is evidence
/// only; the non-clone permit handle held by the issuing owner is what releases
/// the capacity exactly once.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityPermitBinding {
    /// Owner-minted permit identity.
    pub permit_id: String,
    /// Operation identity the permit was granted for.
    pub operation_id: String,
    /// Capacity class the permit draws from.
    pub capacity_class: CapacityClass,
    /// Typed operation class; must admit exactly `capacity_class`.
    pub operation: RequestedOperationClass,
    /// Exact bottleneck dimension granted.
    pub bottleneck: CapacityBottleneck,
    /// Granted amount in the bottleneck unit.
    pub granted_limit: CapacityLimit,
    /// Runtime owner that issued the permit.
    pub capacity_owner_ref: String,
    /// Issuing owner generation.
    pub capacity_owner_generation_ref: ResourceGeneration,
    /// Owner the permit was granted to.
    pub requesting_owner_ref: String,
    /// Requester generation the permit was granted to.
    pub requesting_generation_ref: ResourceGeneration,
    /// Authority Epoch the permit is bound to.
    pub authority_epoch_ref: EpochId,
    /// Profile identity the permit was issued under.
    pub profile_id: String,
    /// Profile revision the permit was issued under.
    pub profile_revision: String,
    /// Issue time in Unix milliseconds.
    pub issued_at_ms: u64,
    /// Expiry time in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Owner evidence references supporting the grant.
    pub owner_evidence_refs: Vec<String>,
}

impl CapacityPermitBinding {
    /// Validates binding legality without consulting any owner counter.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContractError::InvalidField`] naming the first violated
    /// invariant of `[types.CapacityPermitBinding]`.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        if self.permit_id.trim().is_empty() {
            return Err(invalid(
                "permit_id",
                "MISSING_PERMIT_IDENTITY: a binding names one owner-minted permit",
            ));
        }
        if self.operation_id.trim().is_empty() {
            return Err(invalid(
                "operation_id",
                "MISSING_OPERATION_IDENTITY: a binding names one operation identity",
            ));
        }
        if self.operation.capacity_class() != self.capacity_class {
            return Err(invalid(
                "operation",
                "CLASS_MISMATCH: the operation tag admits exactly the bound capacity class",
            ));
        }
        if self.granted_limit.unit != self.bottleneck.unit() {
            return Err(invalid(
                "granted_limit",
                "UNIT_MISMATCH: a binding grants exactly the bottleneck unit",
            ));
        }
        if self.capacity_owner_ref.trim().is_empty() || self.requesting_owner_ref.trim().is_empty()
        {
            return Err(invalid(
                "capacity_owner_ref",
                "MISSING_CAPACITY_OWNER: a binding names the issuing owner and the requester",
            ));
        }
        if self.profile_id.trim().is_empty() || self.profile_revision.trim().is_empty() {
            return Err(invalid(
                "profile_revision",
                "STALE_PROFILE: a binding carries one profile identity and revision",
            ));
        }
        if self.expires_at_ms <= self.issued_at_ms {
            return Err(invalid(
                "expires_at_ms",
                "EXPIRED_AT_ISSUE: a binding expires strictly after it is issued",
            ));
        }
        validate_canonical_refs("owner_evidence_refs", &self.owner_evidence_refs)
    }

    /// Returns `true` only when the binding exactly matches the request it was
    /// issued for: same operation tag and identity, same bottleneck with the
    /// same unit and amount, same requester owner and generation, same Authority
    /// Epoch and same profile identity and revision. Changed content never
    /// matches; it conflicts instead of replaying.
    #[must_use]
    pub fn matches_request(&self, request: &CapacityRequest) -> bool {
        self.operation == request.operation
            && self.operation_id == request.operation_id
            && self.bottleneck == request.requested_bottleneck
            && self.granted_limit == request.requested_limit
            && self.requesting_owner_ref == request.requesting_owner_ref
            && self.requesting_generation_ref == request.requesting_generation_ref
            && self
                .authority_epoch_ref
                .is_same_authority(&request.authority_epoch_ref)
            && self.profile_id == request.profile_id
            && self.profile_revision == request.profile_revision
    }
}

/// Terminal disposition of one permit (frozen `[types.PermitTerminalDisposition]`).
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermitTerminalDisposition {
    /// Released by its holder; capacity returned exactly once.
    Released,
    /// Released through owner reconciliation after restart or doubt.
    ReconciledReleased,
    /// Possibly leaked; excluded until the owner reconciles it.
    LeakSuspected,
    /// Owner is stale; excluded until the current owner reconciles it.
    StaleOwner,
    /// Terminal state is unknown; excluded until reconciled.
    Unknown,
}

impl PermitTerminalDisposition {
    /// Returns the exact frozen contract identifier.
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::Released => "RELEASED",
            Self::ReconciledReleased => "RECONCILED_RELEASED",
            Self::LeakSuspected => "LEAK_SUSPECTED",
            Self::StaleOwner => "STALE_OWNER",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// One owner-produced release record (frozen `[types.CapacityReleaseEvidence]`).
///
/// The record never exceeds or changes the granted unit and quantity: only a
/// record whose released limit equals the granted limit matches its binding
/// (see [`Self::matches_binding`]). Stale or unknown ownership never silently
/// increases available capacity; restart reconciliation replays this durable
/// operation/permit evidence rather than resetting a counter.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityReleaseEvidence {
    /// Permit identity being released.
    pub permit_id: String,
    /// Operation identity the permit was granted for.
    pub operation_id: String,
    /// How the permit reached its terminal state.
    pub terminal_disposition: PermitTerminalDisposition,
    /// Released amount; must equal the granted limit of the binding.
    pub released_limit: CapacityLimit,
    /// Owner generation observed at release.
    pub observed_owner_generation_ref: ResourceGeneration,
    /// Authority Epoch observed at release.
    pub authority_epoch_ref: EpochId,
    /// Profile identity observed at release.
    pub profile_id: String,
    /// Profile revision observed at release.
    pub profile_revision: String,
    /// Release time in Unix milliseconds.
    pub released_at_ms: u64,
    /// Evidence references supporting the release.
    pub evidence_refs: Vec<String>,
    /// Reconciliation reference for restart/doubt releases.
    pub reconciliation_ref: String,
}

impl CapacityReleaseEvidence {
    /// Validates release-record legality without moving any owner counter.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContractError::InvalidField`] naming the first violated
    /// invariant of `[types.CapacityReleaseEvidence]`.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        if self.permit_id.trim().is_empty() {
            return Err(invalid(
                "permit_id",
                "MISSING_PERMIT_IDENTITY: a release names one permit",
            ));
        }
        if self.operation_id.trim().is_empty() {
            return Err(invalid(
                "operation_id",
                "MISSING_OPERATION_IDENTITY: a release names one operation identity",
            ));
        }
        if self.profile_id.trim().is_empty()
            || self.profile_revision.trim().is_empty()
            || self.reconciliation_ref.trim().is_empty()
        {
            return Err(invalid(
                "reconciliation_ref",
                "STALE_PROFILE: a release carries one profile identity, revision and reconciliation reference",
            ));
        }
        validate_canonical_refs("evidence_refs", &self.evidence_refs)
    }

    /// Returns `true` only when the release exactly matches the binding it
    /// closes: same permit and operation identities, released limit equal to
    /// the granted limit, same observed owner generation, same Authority Epoch
    /// and same profile identity and revision. A release that changes the
    /// unit, quantity, owner, epoch or profile never matches.
    #[must_use]
    pub fn matches_binding(&self, binding: &CapacityPermitBinding) -> bool {
        self.permit_id == binding.permit_id
            && self.operation_id == binding.operation_id
            && self.released_limit == binding.granted_limit
            && self.observed_owner_generation_ref == binding.capacity_owner_generation_ref
            && self
                .authority_epoch_ref
                .is_same_authority(&binding.authority_epoch_ref)
            && self.profile_id == binding.profile_id
            && self.profile_revision == binding.profile_revision
    }
}

fn invalid(field: &'static str, reason: &'static str) -> RuntimeContractError {
    RuntimeContractError::InvalidField { field, reason }
}

/// A set-like field is canonical and duplicate-free when it is strictly
/// ascending; the strict order also rejects a repeated reference.
fn validate_canonical_refs(
    field: &'static str,
    references: &[String],
) -> Result<(), RuntimeContractError> {
    let canonical = references.windows(2).all(|pair| pair[0] < pair[1]);
    if canonical {
        return Ok(());
    }
    Err(invalid(
        field,
        "NONCANONICAL_PROFILE: set-like fields are canonical and duplicate-free",
    ))
}
