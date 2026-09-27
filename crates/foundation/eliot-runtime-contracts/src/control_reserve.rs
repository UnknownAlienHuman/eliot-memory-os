//! Closed control-reserve capacity vocabulary owned by runtime contracts.
//!
//! This is descriptive contract data only. Physical acquisition, enforcement,
//! and capacity observation remain with each bottleneck's runtime owner.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
