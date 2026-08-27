//! P-03/I9 physical process identity — Architecture micro-module.
//! Isolates `PhysicalProcessBinding`, `SuspendedProcessIdentity`, `SuspendedLaunchEvidence`, `ProcessIdentity`.
//! Authority invariant: grants no dispatch authority; parent retains authority, state, and receipt ownership.
//! No launch/effect/authority/ORS ownership.

use super::{
    ContractError, Generation, ImageId, JobId, MAX_EXECUTOR_JOB_NAME_UTF16,
    MAX_PROCESS_IMAGE_PATH_UTF16, ProcessId, ProcessTreeId, SessionId, validate_hex_digest,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Inert physical process/Job binding observed by P-02 from retained OS handles.
///
/// This value grants no dispatch authority. It keeps the executor-created Job
/// identity separate from the caller's logical [`JobId`] and gives recovery
/// consumers the exact PID/start/image tuple required to reject PID reuse.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalProcessBinding {
    process_id: u32,
    start_time_100ns: u64,
    image_path: String,
    executor_job_name: String,
}

impl PhysicalProcessBinding {
    /// Creates one bounded physical binding from fresh executor evidence.
    pub fn new(
        process_id: u32,
        start_time_100ns: u64,
        image_path: impl Into<String>,
        executor_job_name: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let binding = Self {
            process_id,
            start_time_100ns,
            image_path: image_path.into(),
            executor_job_name: executor_job_name.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), ContractError> {
        if self.process_id == 0 || self.start_time_100ns == 0 {
            return Err(ContractError::InvalidValue {
                field: "physical_process_binding",
                reason: "process id and creation time must be non-zero",
            });
        }
        let image_length = self.image_path.encode_utf16().count();
        if self.image_path.trim().is_empty()
            || image_length > MAX_PROCESS_IMAGE_PATH_UTF16
            || self.image_path.chars().any(char::is_control)
        {
            return Err(ContractError::InvalidValue {
                field: "physical_process_binding.image_path",
                reason: "must be a non-empty bounded control-free image locator",
            });
        }
        let job_length = self.executor_job_name.encode_utf16().count();
        if self.executor_job_name.trim().is_empty()
            || job_length > MAX_EXECUTOR_JOB_NAME_UTF16
            || self.executor_job_name.chars().any(char::is_control)
        {
            return Err(ContractError::InvalidValue {
                field: "physical_process_binding.executor_job_name",
                reason: "must be one bounded control-free executor Job identity",
            });
        }
        Ok(())
    }

    /// Returns the exact OS process identifier.
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }

    /// Returns the exact OS process creation marker.
    pub const fn start_time_100ns(&self) -> u64 {
        self.start_time_100ns
    }

    /// Returns the executor-observed process image path.
    pub fn image_path(&self) -> &str {
        &self.image_path
    }

    /// Returns the executor-created OS Job identity, never the logical `JobId`.
    pub fn executor_job_name(&self) -> &str {
        &self.executor_job_name
    }
}

/// Fresh P-02 evidence for a child that is assigned to its Job but still suspended.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuspendedProcessIdentity {
    pub(super) process_id: ProcessId,
    pub(super) process_tree_id: ProcessTreeId,
    pub(super) job_id: JobId,
    pub(super) image_id: ImageId,
    pub(super) session_id: SessionId,
    pub(super) generation: Generation,
    pub(super) physical: PhysicalProcessBinding,
    pub(super) created_suspended_at_unix_ms: u64,
    pub(super) executable_sha256: String,
}

/// Fresh provider-neutral evidence captured from the suspended child before
/// any resume effect. The physical identity is intentionally reduced to the
/// stable file identity fields needed by Kernel admission.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuspendedLaunchEvidence {
    requested_executable: String,
    executable_volume_serial_number: u32,
    executable_file_index: u64,
}

impl SuspendedLaunchEvidence {
    /// Creates exact suspended-child executable evidence.
    pub fn new(
        requested_executable: impl Into<String>,
        executable_volume_serial_number: u32,
        executable_file_index: u64,
    ) -> Result<Self, ContractError> {
        let evidence = Self {
            requested_executable: requested_executable.into(),
            executable_volume_serial_number,
            executable_file_index,
        };
        if evidence.requested_executable.trim().is_empty()
            || evidence.requested_executable.chars().any(char::is_control)
            || evidence.executable_volume_serial_number == 0
            || evidence.executable_file_index == 0
        {
            return Err(ContractError::InvalidValue {
                field: "suspended_launch_evidence",
                reason: "requested path and executable identity must be valid",
            });
        }
        Ok(evidence)
    }

    /// Returns the exact executable path requested by the suspended child.
    pub fn requested_executable(&self) -> &str {
        &self.requested_executable
    }

    /// Returns the volume serial number observed from the suspended image.
    pub const fn executable_volume_serial_number(&self) -> u32 {
        self.executable_volume_serial_number
    }

    /// Returns the file index observed from the suspended image.
    pub const fn executable_file_index(&self) -> u64 {
        self.executable_file_index
    }
}

impl SuspendedProcessIdentity {
    /// Creates exact pre-resume identity from fresh retained-handle evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        process_id: ProcessId,
        process_tree_id: ProcessTreeId,
        job_id: JobId,
        image_id: ImageId,
        session_id: SessionId,
        generation: Generation,
        physical: PhysicalProcessBinding,
        created_suspended_at_unix_ms: u64,
        executable_sha256: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let identity = Self {
            process_id,
            process_tree_id,
            job_id,
            image_id,
            session_id,
            generation,
            physical,
            created_suspended_at_unix_ms,
            executable_sha256: executable_sha256.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub(super) fn validate(&self) -> Result<(), ContractError> {
        self.process_id.validate()?;
        self.process_tree_id.validate()?;
        self.job_id.validate()?;
        self.image_id.validate()?;
        self.session_id.validate()?;
        self.physical.validate()?;
        if self.created_suspended_at_unix_ms == 0 {
            return Err(ContractError::InvalidValue {
                field: "suspended_process_identity",
                reason: "suspended observation time must be non-zero",
            });
        }
        validate_hex_digest("executable_sha256", &self.executable_sha256)
    }

    /// Returns the physical process identity.
    pub const fn process_id(&self) -> &ProcessId {
        &self.process_id
    }

    /// Returns the Job identity.
    pub const fn job_id(&self) -> &JobId {
        &self.job_id
    }

    /// Returns the mandatory inert physical OS process/Job binding.
    pub const fn physical(&self) -> &PhysicalProcessBinding {
        &self.physical
    }

    /// Returns the observed executable digest captured before resume.
    pub fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }
}

/// Exact identity after the validated suspended child was resumed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub(super) suspended: SuspendedProcessIdentity,
    resumed_at_unix_ms: u64,
}

impl ProcessIdentity {
    pub(super) fn after_resume(
        suspended: SuspendedProcessIdentity,
        resumed_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        if resumed_at_unix_ms < suspended.created_suspended_at_unix_ms {
            return Err(ContractError::InvalidValue {
                field: "resumed_at_unix_ms",
                reason: "resume cannot precede suspended creation",
            });
        }
        Ok(Self {
            suspended,
            resumed_at_unix_ms,
        })
    }

    /// Returns the physical process identity.
    pub const fn process_id(&self) -> &ProcessId {
        &self.suspended.process_id
    }

    /// Returns the process-tree identity.
    pub const fn process_tree_id(&self) -> &ProcessTreeId {
        &self.suspended.process_tree_id
    }

    /// Returns the Job identity.
    pub const fn job_id(&self) -> &JobId {
        &self.suspended.job_id
    }

    /// Returns the exact image identity.
    pub const fn image_id(&self) -> &ImageId {
        &self.suspended.image_id
    }

    /// Returns the session identity.
    pub const fn session_id(&self) -> &SessionId {
        &self.suspended.session_id
    }

    /// Returns the generation.
    pub const fn generation(&self) -> Generation {
        self.suspended.generation
    }

    /// Returns the OS PID lookup value.
    pub const fn pid(&self) -> u32 {
        self.suspended.physical.process_id()
    }

    /// Returns the exact executor-observed physical OS process/Job binding.
    pub const fn physical(&self) -> &PhysicalProcessBinding {
        self.suspended.physical()
    }

    /// Returns the observed executable digest.
    pub fn executable_sha256(&self) -> &str {
        &self.suspended.executable_sha256
    }

    /// Returns the exact resume time.
    pub const fn resumed_at_unix_ms(&self) -> u64 {
        self.resumed_at_unix_ms
    }
}
