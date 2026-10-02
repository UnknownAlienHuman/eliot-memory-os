//! Physical Windows Job and process lifecycle only.
//!
//! Architecture (verified):
//! - `A13.1` (`docs/architecture/A13-01-let-it-fail-locally.md`)
//! - `A13.2` (`docs/architecture/A13-02-kernel-and-failure-domains.md`)
//! - `A13.3` (`docs/architecture/A13-03-module-supervision-and-doctor.md`)
//!
//! Implementation (verified):
//! - `I14.20` runtime lifecycle vocabulary, including durable job execution
//!   (`docs/architecture/I14-20-canonical-runtime-lifecycle-vocabulary.md`)
//! - `I10.3` execution-identity boundary on Windows
//!   (`docs/architecture/I10-03-bridge-types.md`)
//! - Appendix A restart child classes
//!   (`docs/architecture/APPENDIX-A-modulegeneration-lifecycle-projection.md`)
//!
//! Topology (verified):
//! - `I2.1` crate-rich extraction of a capability behind an owned contract
//!   (`docs/architecture/I02-01-primary-decision-crate-rich-process-sparse-owner-sparse.md`)
//! - `I2.23` capability-family topology and crate-extraction decisions
//!   (`docs/architecture/I02-23-capability-family-topology-and-crate-extraction-decisions.md`)
//!
//! Normative sources: `docs/ARCHITECTURE_CONTRACT.md` and the canonical
//! sharded fragments named per anchor above.
//!
//! This module states physical Job/process lifecycle only: creation,
//! suspended launch, consuming validation-before-resume, assignment,
//! kill-on-close, termination, and reap. It forbids authority/token/lease
//! minting, semantic ownership/decision/readiness, retry/default/repair and
//! carries no semantic authority.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FileIdentity;
use crate::OwnedKernelHandle;
use crate::OwnedProcessHandle;
use crate::OwnedSecurityDescriptor;
use crate::PinnedExecutable;
use crate::ProcessIdentity;
use crate::WindowsAdapterError;
use crate::command_environment;
use crate::command_line;
use crate::file_identity;
use crate::inspect_process_handle;
use crate::job_process_ids;
use crate::last_windows_adapter_error;
use crate::nul_terminated_wide;
use crate::os_has_nul;
use crate::same_windows_path;
use crate::validate_complete_environment;
use crate::wait_for_job_empty;
use crate::windows_adapter_from_io;

#[path = "process_job_observation_models.rs"]
mod process_job_observation_models;

pub use process_job_observation_models::{
    JobObservationGap, JobProcessHistory, ProcessObservation, RecoverableJobBinding,
};

#[cfg(windows)]
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct JobObjectIdentity {
    name: String,
}

#[cfg(windows)]
impl JobObjectIdentity {
    /// Validates one exact Job Object name.
    ///
    /// # Errors
    /// Returns `InvalidInput` for an empty name, embedded NUL, or a name wider
    /// than the bounded Windows object-manager representation used here.
    pub fn new(name: impl Into<String>) -> Result<Self, WindowsAdapterError> {
        let name = name.into();
        if !valid_job_object_name(&name) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self { name })
    }

    /// Revalidates shape after deserializing a raw durable binding.
    ///
    /// This check grants no authority and does not prove that the named kernel
    /// object exists. [`RecoverableJobObject::open`] still has to reopen the
    /// Job and compare a fresh handle-bound root observation.
    ///
    /// # Errors
    /// Returns `InvalidInput` for an invalid or unbounded object-manager name.
    pub fn validate(&self) -> Result<(), WindowsAdapterError> {
        if valid_job_object_name(&self.name) {
            Ok(())
        } else {
            Err(WindowsAdapterError::InvalidInput)
        }
    }

    /// Returns the exact Windows object-manager name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reports whether this durable name is a Host-owned outer kill domain Job
    /// Object name rather than a per-generation/per-attempt nested name.
    ///
    /// `I1.6` puts kill-on-close at the outer ownership boundary, so a nested
    /// Job Object name must never be treated as an outer kill domain.
    #[must_use]
    pub fn is_host_outer_kill_domain_name(&self) -> bool {
        outer_kill_domain_of_job_name(&self.name).is_some()
    }
}

/// Resolves the Host-owned outer kill domain that owns `job_name`.
///
/// The domain is a total function of the durable Job Object name, so the
/// owner identity on an outer Job Object record can never disagree with the
/// name a launcher presented. A per-generation/per-attempt nested Job Object
/// name resolves to `None`: nesting never mints a second outer kill domain.
#[cfg(windows)]
fn outer_kill_domain_of_job_name(job_name: &str) -> Option<OuterKillDomain> {
    [
        OuterKillDomain::Kernel,
        OuterKillDomain::Store,
        OuterKillDomain::Watchdog,
    ]
    .into_iter()
    .find(|domain| domain.owns_host_job_name(job_name))
}

#[cfg(windows)]
fn valid_job_object_name(name: &str) -> bool {
    let length = name.encode_utf16().count();
    length != 0 && length <= 240 && !name.chars().any(char::is_control)
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JobObjectLimits {
    cpu_time_ms: Option<u64>,
    memory_bytes: Option<u64>,
    active_process_limit: Option<u32>,
    /// Hard CPU rate-control ceiling in `1..=100`, installed on the Job Object
    /// as a hard-cap `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION`.
    cpu_rate_control_percent: Option<u16>,
}

#[cfg(windows)]
impl JobObjectLimits {
    /// Creates validated optional Job limits.
    ///
    /// # Errors
    /// Returns `InvalidInput` when a supplied ceiling is zero or cannot be
    /// represented by the Win32 Job Object structures, or when a supplied CPU
    /// rate-control percentage is outside `1..=100`.
    pub fn new(
        cpu_time_ms: Option<u64>,
        memory_bytes: Option<u64>,
        active_process_limit: Option<u32>,
        cpu_rate_control_percent: Option<u16>,
    ) -> Result<Self, WindowsAdapterError> {
        if matches!(cpu_time_ms, Some(0))
            || matches!(memory_bytes, Some(0))
            || matches!(active_process_limit, Some(0))
            || cpu_rate_control_percent.is_some_and(|percent| !(1..=100).contains(&percent))
            || memory_bytes.is_some_and(|value| usize::try_from(value).is_err())
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        if let Some(cpu_time_ms) = cpu_time_ms {
            let ticks = cpu_time_ms
                .checked_mul(10_000)
                .ok_or(WindowsAdapterError::InvalidInput)?;
            i64::try_from(ticks).map_err(|_| WindowsAdapterError::InvalidInput)?;
        }
        Ok(Self {
            cpu_time_ms,
            memory_bytes,
            active_process_limit,
            cpu_rate_control_percent,
        })
    }

    /// Creates validated Job limits with a mandatory memory ceiling.
    ///
    /// Worker launch descriptors whose approved profile requires containment
    /// use this constructor: a missing (`None`) memory ceiling fails closed
    /// instead of falling back to the unlimited default. A failed limit is a
    /// typed rejection, never an admitted unlimited Job.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the required memory ceiling is absent, is
    /// zero, or cannot be represented by the Win32 Job Object structures, or
    /// when any other supplied ceiling is zero, out of range, or unrepresentable.
    pub fn require_memory_ceiling(
        cpu_time_ms: Option<u64>,
        memory_bytes: Option<u64>,
        active_process_limit: Option<u32>,
        cpu_rate_control_percent: Option<u16>,
    ) -> Result<Self, WindowsAdapterError> {
        if memory_bytes.is_none() {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Self::new(
            cpu_time_ms,
            memory_bytes,
            active_process_limit,
            cpu_rate_control_percent,
        )
    }

    /// Creates Job limits from the admitted Module Manifest ceilings only.
    ///
    /// `I1.6` states that "CPU, memory, and process limits are set by Module
    /// Manifest", so this constructor takes exactly the three ceilings the Job
    /// Object installs â€” the admitted CPU rate-control percentage, working-set
    /// and active-process limits â€” and installs no CPU-*time* ceiling at all.
    /// `ManifestResourceLimits` records a CPU rate-control percentage, not a
    /// CPU-time budget; a caller-supplied CPU-time budget would be unbounded by
    /// the manifest, so this constructor has no parameter that could supply one.
    ///
    /// All three ceilings are mandatory. An absent admitted ceiling fails closed
    /// instead of falling back to the unlimited default, because an unlimited
    /// Job is not a contained one â€” and an absent CPU rate is not "no CPU
    /// limit" either: it would let a module exceed the CPU ceiling its manifest
    /// admits.
    ///
    /// # Errors
    /// Returns `InvalidInput` when any admitted ceiling is absent, is zero or
    /// out of range, or cannot be represented by the Win32 Job Object structures.
    pub fn require_admitted_job_limits(
        memory_bytes: Option<u64>,
        active_process_limit: Option<u32>,
        cpu_rate_control_percent: Option<u16>,
    ) -> Result<Self, WindowsAdapterError> {
        if memory_bytes.is_none()
            || active_process_limit.is_none()
            || cpu_rate_control_percent.is_none()
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Self::new(
            None,
            memory_bytes,
            active_process_limit,
            cpu_rate_control_percent,
        )
    }

    /// Returns the admitted CPU-time ceiling, if one was installed.
    #[must_use]
    pub const fn cpu_time_ms(&self) -> Option<u64> {
        self.cpu_time_ms
    }

    /// Returns the admitted Job memory ceiling in bytes, if one was installed.
    ///
    /// `None` is an explicitly unlimited Job, never a zero reading: callers
    /// binding requested and observed enforced limits must preserve the
    /// distinction instead of projecting unlimited as contained.
    #[must_use]
    pub const fn memory_bytes(&self) -> Option<u64> {
        self.memory_bytes
    }

    /// Returns the admitted active-process ceiling, if one was installed.
    #[must_use]
    pub const fn active_process_limit(&self) -> Option<u32> {
        self.active_process_limit
    }

    /// Returns the admitted CPU rate-control ceiling in `1..=100`, if one was
    /// installed.
    ///
    /// `None` is an explicitly unlimited CPU, never a zero reading, so the
    /// admitted-vs-observed comparison that attests an installed Job keeps the
    /// same distinction the memory ceiling preserves.
    #[must_use]
    pub const fn cpu_rate_control_percent(&self) -> Option<u16> {
        self.cpu_rate_control_percent
    }
}

/// Owner identity of one Host-owned outer Job Object kill domain.
///
/// `I1.6` requires that "Watchdog and Kernel do not share a child-kill
/// domain", that "Kernel descendants remain inside the Host-owned Kernel Job
/// Object and MAY additionally enter nested per-Module/per-attempt Job
/// Objects", and that "the process tree receives kill-on-close at its outer
/// ownership boundary".
///
/// The domain is bound to the object-manager name by
/// [`OuterKillDomain::owns_host_job_name`]: a launcher must present the
/// `Local\Eliot-Host-<domain>-<suffix>` Job Object of the domain it claims, so
/// a Kernel launcher cannot present the Watchdog domain's Job Object and a
/// Watchdog launcher cannot present the Kernel domain's Job Object.
#[cfg(windows)]
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OuterKillDomain {
    /// The Host-owned Kernel Job Object; every Kernel descendant stays in it.
    Kernel,
    /// The Host-owned canonical-store Job Object, launched as its own branch.
    Store,
    /// The independent Watchdog Job Object; it never shares a kill domain with
    /// the Kernel, so closing the Kernel Job Object cannot kill it.
    Watchdog,
}

#[cfg(windows)]
impl OuterKillDomain {
    /// Returns the exact name fragment this domain contributes to a Host-owned
    /// outer Job Object name.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Kernel => "Kernel",
            Self::Store => "Store",
            Self::Watchdog => "Watchdog",
        }
    }

    /// Returns the exact object-manager prefix of this domain's Host-owned
    /// outer Job Object.
    #[must_use]
    pub const fn host_job_name_prefix(self) -> &'static str {
        match self {
            Self::Kernel => "Local\\Eliot-Host-Kernel-",
            Self::Store => "Local\\Eliot-Host-Store-",
            Self::Watchdog => "Local\\Eliot-Host-Watchdog-",
        }
    }

    /// Reports whether `job_name` is exactly the Host-owned outer Job Object
    /// name of this kill domain.
    ///
    /// A per-generation/per-attempt Job Object name is not a Host-owned outer
    /// name, so this reports `false` for nested Job Objects: nesting never
    /// mints a second outer kill domain.
    #[must_use]
    pub fn owns_host_job_name(self, job_name: &str) -> bool {
        job_name
            .strip_prefix(self.host_job_name_prefix())
            .is_some_and(|suffix| !suffix.is_empty())
    }

    /// Returns the other Host-owned kill domain a containment probe for this
    /// domain must contrast with.
    ///
    /// The acceptance clause requires that closing one outer Job Object kills
    /// that domain's descendants and leaves a different domain's descendants
    /// running, so a probe always needs a second, distinct domain.
    #[must_use]
    pub const fn contrasting_domain(self) -> Self {
        match self {
            Self::Kernel | Self::Store => Self::Watchdog,
            Self::Watchdog => Self::Kernel,
        }
    }
}

#[cfg(windows)]
static JOB_OBJECT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// RAII wrapper for a named Windows Job Object configured to terminate
/// assigned processes when the sole owning handle closes.
///
/// `outer_kill_domain` is the owner identity carried on the Job Object record.
/// It is `Some` only for a Host-owned outer kill domain Job Object; a
/// per-generation/per-attempt nested Job Object carries `None` because
/// nesting must never mint a second outer kill domain.
#[cfg(windows)]
pub struct JobObject {
    handle: windows_sys::Win32::Foundation::HANDLE,
    identity: JobObjectIdentity,
    outer_kill_domain: Option<OuterKillDomain>,
}

// SAFETY: a Job Object handle is process-global and uniquely owned here.
#[cfg(windows)]
unsafe impl Send for JobObject {}

#[cfg(windows)]
impl JobObject {
    /// Creates a Job Object with kill-on-close configured before publication.
    ///
    /// # Errors
    /// Returns a typed adapter error when creation or configuration fails.
    pub fn new_kill_on_close() -> Result<Self, WindowsAdapterError> {
        let sequence = JOB_OBJECT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let identity = JobObjectIdentity::new(format!(
            "Local\\Eliot-P02-{}-{sequence}",
            std::process::id()
        ))?;
        Self::new_named_kill_on_close(identity)
    }

    /// Creates a fresh named Job Object and rejects an existing name.
    ///
    /// The protected DACL grants full access only to `LocalSystem` and the
    /// creating owner. A new generation therefore cannot silently join an
    /// older Job with the same durable identity.
    ///
    /// # Errors
    /// Returns `AlreadyExists` for a name collision or another typed adapter
    /// error when Windows rejects creation or limit configuration.
    pub fn new_named_kill_on_close(
        identity: JobObjectIdentity,
    ) -> Result<Self, WindowsAdapterError> {
        Self::new_named_kill_on_close_with_limits(identity, JobObjectLimits::default())
    }

    /// Creates a fresh named kill-on-close Job with exact resource ceilings.
    ///
    /// All limits are installed before any process can be assigned.
    ///
    /// # Errors
    /// Returns a typed adapter error for name collision, invalid conversion,
    /// or rejected Job configuration.
    pub fn new_named_kill_on_close_with_limits(
        identity: JobObjectIdentity,
        resource_limits: JobObjectLimits,
    ) -> Result<Self, WindowsAdapterError> {
        Self::create_named_kill_on_close(identity, resource_limits, None)
    }

    /// Creates a fresh named kill-on-close Job Object owned by one Host-owned
    /// outer kill domain.
    ///
    /// The owner identity is admitted only when the durable Job Object name is
    /// exactly this domain's `Local\Eliot-Host-<domain>-<suffix>` name, so a
    /// launcher cannot create, reopen, or attach a child to another domain's
    /// outer kill domain Job Object.
    ///
    /// # Errors
    /// Returns `IdentityMismatch` when the name is not this kill domain's
    /// outer Job Object name, and otherwise the typed adapter errors of
    /// [`JobObject::new_named_kill_on_close_with_limits`].
    pub fn new_named_outer_kill_on_close_with_limits(
        outer_kill_domain: OuterKillDomain,
        identity: JobObjectIdentity,
        resource_limits: JobObjectLimits,
    ) -> Result<Self, WindowsAdapterError> {
        if !outer_kill_domain.owns_host_job_name(identity.name()) {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Self::create_named_kill_on_close(identity, resource_limits, Some(outer_kill_domain))
    }

    /// Returns the Host-owned outer kill domain this Job Object is the
    /// kill-on-close boundary of, or `None` for a per-generation/per-attempt
    /// nested Job Object that must never mint a second outer kill domain.
    #[must_use]
    pub const fn outer_kill_domain(&self) -> Option<OuterKillDomain> {
        self.outer_kill_domain
    }

    fn create_named_kill_on_close(
        identity: JobObjectIdentity,
        resource_limits: JobObjectLimits,
        outer_kill_domain: Option<OuterKillDomain>,
    ) -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
            JOB_OBJECT_LIMIT_JOB_TIME, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        let name = nul_terminated_wide(std::ffi::OsStr::new(identity.name()))
            .map_err(|error| windows_adapter_from_io(&error))?;
        let descriptor = OwnedSecurityDescriptor::for_job_owner()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| WindowsAdapterError::Failed)?,
            lpSecurityDescriptor: descriptor.raw,
            bInheritHandle: 0,
        };
        // SAFETY: name, descriptor and attributes remain live for the call.
        let handle = unsafe { CreateJobObjectW(&raw const attributes, name.as_ptr()) };
        // SAFETY: GetLastError immediately observes the creation disposition.
        let creation_error = unsafe { GetLastError() };
        if handle.is_null() {
            return Err(last_windows_adapter_error());
        }
        if creation_error == ERROR_ALREADY_EXISTS {
            // SAFETY: this path owns the handle returned for the old object.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
            return Err(WindowsAdapterError::AlreadyExists);
        }
        let mut job_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if let Some(cpu_time_ms) = resource_limits.cpu_time_ms {
            let ticks = cpu_time_ms
                .checked_mul(10_000)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or(WindowsAdapterError::InvalidInput)?;
            job_info.BasicLimitInformation.PerJobUserTimeLimit = ticks;
            job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME;
        }
        if let Some(memory_bytes) = resource_limits.memory_bytes {
            job_info.JobMemoryLimit =
                usize::try_from(memory_bytes).map_err(|_| WindowsAdapterError::InvalidInput)?;
            job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        }
        if let Some(active_process_limit) = resource_limits.active_process_limit {
            job_info.BasicLimitInformation.ActiveProcessLimit = active_process_limit;
            job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        }
        let length = u32::try_from(std::mem::size_of_val(&job_info))
            .map_err(|_| WindowsAdapterError::Failed)?;
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&raw const job_info).cast(),
                length,
            )
        } != 0;
        if !configured {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
            return Err(last_windows_adapter_error());
        }
        // `I1.6` requires the CPU limit too, and Windows carries CPU rate
        // control in its own information class rather than in
        // `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`. Installing it here, from the
        // same admitted value and before any process can be assigned, keeps the
        // Job's CPU at or under the manifest ceiling. Windows rejects the
        // ceiling on this call rather than ignoring it, so a refusal closes the
        // Job Object and fails the creation instead of leaving a Job whose CPU
        // rate is unconstrained.
        if let Some(cpu_rate_control_percent) = resource_limits.cpu_rate_control_percent {
            let configured_rate =
                Self::set_cpu_rate_control_percent(handle, cpu_rate_control_percent);
            if configured_rate.is_err() {
                unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
            }
            configured_rate?;
        }
        Ok(Self {
            handle,
            identity,
            outer_kill_domain,
        })
    }

    /// Returns the durable Job Object identity.
    #[must_use]
    pub const fn identity(&self) -> &JobObjectIdentity {
        &self.identity
    }

    /// Assigns an existing process and returns its exact observed identity.
    ///
    /// # Errors
    /// Returns a typed adapter error for invalid identity, access or assignment failure.
    pub fn assign_process(&self, process_id: u32) -> Result<ProcessIdentity, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
        };
        if process_id == 0 {
            return Err(WindowsAdapterError::InvalidInput);
        }
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA | PROCESS_TERMINATE,
                0,
                process_id,
            )
        };
        if process.is_null() {
            return Err(last_windows_adapter_error());
        }
        let assigned = self.assign_process_handle(process);
        let result = if assigned.is_ok() {
            inspect_process_handle(process_id, process)
                .map_err(|error| windows_adapter_from_io(&error))
        } else {
            Err(assigned.err().unwrap_or(WindowsAdapterError::Failed))
        };
        unsafe { CloseHandle(process) };
        result
    }

    fn assign_process_handle(
        &self,
        process: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), WindowsAdapterError> {
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        if unsafe { AssignProcessToJobObject(self.handle, process) } == 0 {
            Err(last_windows_adapter_error())
        } else {
            Ok(())
        }
    }

    fn contains_process(&self, process_id: u32) -> Result<bool, WindowsAdapterError> {
        job_process_ids(self.handle)
            .map(|processes| processes.into_iter().any(|pid| pid == process_id))
            .map_err(|error| windows_adapter_from_io(&error))
    }

    /// Terminates every process currently assigned to this job.
    ///
    /// # Errors
    /// Returns a typed adapter error when Windows rejects termination.
    pub fn terminate(&self, exit_code: u32) -> Result<(), WindowsAdapterError> {
        let ok = unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.handle, exit_code)
        };
        if ok == 0 {
            Err(last_windows_adapter_error())
        } else {
            Ok(())
        }
    }

    /// Closes the sole owning handle exactly once so the kernel evaluates this
    /// Job Object's `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` limit.
    ///
    /// A launch probe has to observe what Windows does when the *last* handle
    /// to an outer Job Object disappears. A plain `Drop` cannot report that
    /// observation, so the probe releases the handle explicitly and then
    /// re-observes the kernel's decision.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the handle was already released, and a
    /// typed adapter error when Windows rejects the close.
    fn close_owning_handle(&mut self) -> Result<(), WindowsAdapterError> {
        if self.handle.is_null() {
            return Err(WindowsAdapterError::InvalidInput);
        }
        // SAFETY: this value owns the handle and never closes it twice.
        if unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) } == 0 {
            return Err(last_windows_adapter_error());
        }
        self.handle = std::ptr::null_mut();
        Ok(())
    }

    /// Installs the admitted CPU rate-control hard cap on `handle`.
    ///
    /// `I1.6` states that "CPU, memory, and process limits are set by Module
    /// Manifest". Windows carries the CPU ceiling in
    /// `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION` under the
    /// `JobObjectCpuRateControlInformation` class rather than among the
    /// extended-limit flags, so the admitted percentage reaches the Job Object
    /// only here. `JOB_OBJECT_CPU_RATE_CONTROL_ENABLE` with
    /// `JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP` is the rate-cap mode: the Job is
    /// throttled at `CpuRate` cycles per 10,000 and may never run above it,
    /// which is the ceiling the manifest admits. Windows expresses that rate as
    /// a percentage times 100, so the admitted `1..=100` percentage is scaled
    /// here; a rate of zero is rejected by Windows with `ERROR_INVALID_ARGUMENT`,
    /// which is why the admitted range stays `1..=100` rather than merely
    /// non-zero.
    ///
    /// The union's `Weight` arm is deliberately never selected: it is only read
    /// in weight mode, which this call does not enable, and it stays at zero so
    /// no second, unadmitted scheduling weight can reach the Job.
    ///
    /// # Errors
    /// Returns `InvalidInput` for a percentage outside `1..=100`, and the typed
    /// adapter error Windows reports when it rejects the ceiling.
    fn set_cpu_rate_control_percent(
        handle: windows_sys::Win32::Foundation::HANDLE,
        cpu_rate_control_percent: u16,
    ) -> Result<(), WindowsAdapterError> {
        use windows_sys::Win32::System::JobObjects::{
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE, JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
            JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0,
            JobObjectCpuRateControlInformation, SetInformationJobObject,
        };
        if !(1..=100).contains(&cpu_rate_control_percent) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        let rate_control = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
            ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
            Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 {
                CpuRate: u32::from(cpu_rate_control_percent) * 100,
            },
        };
        let length = u32::try_from(std::mem::size_of_val(&rate_control))
            .map_err(|_| WindowsAdapterError::Failed)?;
        // SAFETY: `handle` is the live Job Object owned by this creation path and
        // `rate_control` is a live, correctly sized buffer for the exact class
        // named here, so the call reads only these two values.
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectCpuRateControlInformation,
                (&raw const rate_control).cast(),
                length,
            )
        } != 0;
        if !configured {
            return Err(last_windows_adapter_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for JobObject {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
        }
    }
}

/// The observed verdict of one supported-build Job Object launch probe.
///
/// `I1.6` requires that "startup probes verify the required nesting and
/// kill-on-close semantics on the supported Windows build". This value exists
/// only after a real Windows experiment observed all three properties for
/// `domain` on the running build; it is never a constant and never a
/// permissive default.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobLaunchContainment {
    domain: OuterKillDomain,
    distinct_domain: OuterKillDomain,
}

#[cfg(windows)]
impl JobLaunchContainment {
    /// Returns the Host-owned outer kill domain this verdict was observed for.
    #[must_use]
    pub const fn domain(self) -> OuterKillDomain {
        self.domain
    }

    /// Returns the different Host-owned outer kill domain whose descendant was
    /// observed still running after the probed domain's outer Job Object was
    /// closed.
    #[must_use]
    pub const fn distinct_domain(self) -> OuterKillDomain {
        self.distinct_domain
    }
}

#[cfg(windows)]
static JOB_LAUNCH_CONTAINMENT_PROBES: std::sync::OnceLock<
    std::sync::Mutex<
        std::collections::HashMap<
            OuterKillDomain,
            Result<JobLaunchContainment, WindowsAdapterError>,
        >,
    >,
> = std::sync::OnceLock::new();

/// Probes this Windows build, once per kill domain, for the three containment
/// properties `I1.6` requires a startup probe to verify: that a child is
/// actually assigned to the intended outer Job Object, that a nested
/// per-generation/per-attempt Job Object is permitted for a process already
/// inside an outer Job Object, and that the outer Job Object's kill-on-close
/// limit still governs while a different kill domain is untouched.
///
/// The probe is a real Windows experiment, never a constant. It creates one
/// outer Job Object of `domain` and one of a *different* kill domain, plus one
/// per-generation Job Object, then launches two suspended children of the
/// current image, assigns the first child to `domain`'s outer Job Object and
/// then to the nested Job Object, and assigns the second child to the other
/// domain's outer Job Object. Neither child is ever resumed, so a child can
/// only leave that suspended state by being terminated. The probe then closes
/// the sole owning handle of `domain`'s outer Job Object and re-observes both
/// children.
///
/// A rejected or ineffective nested assignment, or any containment property
/// that cannot be observed, fails closed with a typed adapter error; the
/// caller must not assume nesting, and no caller may fall back to a weaker
/// limit or a shared kill domain.
///
/// # Errors
/// Returns `Unavailable` when this build cannot establish the required
/// nesting, `IdentityMismatch` when a child was not assigned to the intended
/// Job Object or a kill domain did not stay separate, and a typed platform
/// error when the experiment itself cannot be set up.
#[cfg(windows)]
pub fn probe_launch_containment(
    domain: OuterKillDomain,
) -> Result<JobLaunchContainment, WindowsAdapterError> {
    let mut probed = JOB_LAUNCH_CONTAINMENT_PROBES
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
        .lock()
        .map_err(|_| WindowsAdapterError::Failed)?;
    if let Some(observed) = probed.get(&domain) {
        return *observed;
    }
    let observed = observe_launch_containment(domain);
    probed.insert(domain, observed);
    observed
}

/// Requires this build's observed containment verdict for `outer_kill_domain`
/// before any child process may be created.
///
/// The verdict must be the one observed for exactly this domain and must have
/// contrasted it against a different kill domain. Anything else means the
/// required containment was not established, so the launch fails closed here
/// instead of proceeding with a weaker limit or a shared kill domain.
#[cfg(windows)]
fn require_probed_outer_kill_domain(
    outer_kill_domain: OuterKillDomain,
) -> Result<(), WindowsAdapterError> {
    let containment = probe_launch_containment(outer_kill_domain)?;
    if containment.domain() != outer_kill_domain
        || containment.distinct_domain() == outer_kill_domain
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(())
}

/// One outer Job Object's own kill-on-close flag and resource ceilings, read
/// back from the live kernel object rather than from what a launcher intended.
///
/// `I1.6` puts kill-on-close at the outer ownership boundary and requires that
/// "the process tree receives kill-on-close at its outer ownership boundary",
/// and it requires that "CPU, memory, and process limits are set by Module
/// Manifest". Reading those values back through
/// [`QueryInformationJobObject`](windows_sys::Win32::System::JobObjects::QueryInformationJobObject)
/// is what makes the two claims observations: a flag or a ceiling that is absent
/// on the reopened object cannot be attested by a probe that ran against a
/// different Job Object, and the four explicitly optional ceilings of
/// [`JobObjectLimits`] are preserved as `None` instead of being collapsed onto a
/// zero reading.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObservedJobContainment {
    kill_on_close: bool,
    limits: JobObjectLimits,
}

#[cfg(windows)]
impl ObservedJobContainment {
    /// Returns whether the observed Job Object really carries
    /// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
    const fn kill_on_close(&self) -> bool {
        self.kill_on_close
    }

    /// Returns the resource ceilings this exact Job Object actually carries, as
    /// read back from it rather than as they were requested.
    const fn limits(&self) -> &JobObjectLimits {
        &self.limits
    }
}

/// Reads one live Job Object's kill-on-close flag and resource ceilings.
///
/// This is a per-launch observation of one exact Job handle. It is deliberately
/// separate from [`probe_launch_containment`]: that verdict is build-scoped
/// platform capability observed on temporary probe Job Objects, while this is
/// what THIS reopened outer Job actually carries, so an unrelated probe success
/// can never stand in for it.
///
/// # Errors
/// Returns `Unavailable` when Windows will not answer the query for this Job,
/// and `InvalidInput` when the readback cannot be represented as
/// [`JobObjectLimits`].
#[cfg(windows)]
fn observed_job_containment(
    job: windows_sys::Win32::Foundation::HANDLE,
) -> Result<ObservedJobContainment, WindowsAdapterError> {
    use windows_sys::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_JOB_TIME,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, QueryInformationJobObject,
    };
    let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    let length = u32::try_from(std::mem::size_of_val(&information))
        .map_err(|_| WindowsAdapterError::Failed)?;
    // SAFETY: `job` is a live handle this module owns for the whole call and
    // `information` is a writable, correctly sized, zeroed buffer for the exact
    // class named here; the returned length pointer is a live out parameter.
    if unsafe {
        QueryInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&raw mut information).cast(),
            length,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(WindowsAdapterError::Unavailable);
    }
    let flags = information.BasicLimitInformation.LimitFlags;
    let cpu_rate_control_percent = observed_cpu_rate_control_percent(job)?;
    Ok(ObservedJobContainment {
        kill_on_close: flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0,
        limits: JobObjectLimits::new(
            if flags & JOB_OBJECT_LIMIT_JOB_TIME != 0 {
                Some(
                    u64::try_from(information.BasicLimitInformation.PerJobUserTimeLimit)
                        .ok()
                        .and_then(|ticks| ticks.checked_div(10_000))
                        .ok_or(WindowsAdapterError::InvalidInput)?,
                )
            } else {
                None
            },
            if flags & JOB_OBJECT_LIMIT_JOB_MEMORY != 0 {
                Some(
                    u64::try_from(information.JobMemoryLimit)
                        .map_err(|_| WindowsAdapterError::InvalidInput)?,
                )
            } else {
                None
            },
            if flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS != 0
                && information.BasicLimitInformation.ActiveProcessLimit != 0
            {
                // `ActiveProcessLimit == 0` is the documented unlimited reading
                // and is deliberately not reported as a ceiling.
                Some(information.BasicLimitInformation.ActiveProcessLimit)
            } else {
                None
            },
            cpu_rate_control_percent,
        )?,
    })
}

/// Reads one live Job Object's CPU rate-control ceiling as a percentage.
///
/// This is the read-back half of [`JobObject::set_cpu_rate_control_percent`], so
/// the admitted percentage is compared against what the Job Object really
/// carries, exactly as the memory, process, and CPU-time ceilings are. Only a
/// hard cap is reported: a Job carrying CPU rate control in any other mode
/// (weight-based, or min/max rate) carries a ceiling this module never admitted
/// and never installed, so it is reported as `None` and the admitted-limits
/// comparison refuses rather than comparing unrelated units.
///
/// # Errors
/// Returns `Unavailable` when Windows will not answer the query for this Job,
/// and `InvalidInput` when the observed rate is not a whole percentage in
/// `1..=100`.
#[cfg(windows)]
fn observed_cpu_rate_control_percent(
    job: windows_sys::Win32::Foundation::HANDLE,
) -> Result<Option<u16>, WindowsAdapterError> {
    use windows_sys::Win32::System::JobObjects::{
        JOB_OBJECT_CPU_RATE_CONTROL_ENABLE, JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
        JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
        JobObjectCpuRateControlInformation, QueryInformationJobObject,
    };
    let mut rate_control = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION::default();
    let length = u32::try_from(std::mem::size_of_val(&rate_control))
        .map_err(|_| WindowsAdapterError::Failed)?;
    // SAFETY: `job` is a live handle this module owns for the whole call and
    // `rate_control` is a writable, correctly sized, zeroed buffer for the exact
    // class named here; the returned length pointer is a live out parameter.
    if unsafe {
        QueryInformationJobObject(
            job,
            JobObjectCpuRateControlInformation,
            (&raw mut rate_control).cast(),
            length,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(WindowsAdapterError::Unavailable);
    }
    if rate_control.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_ENABLE == 0
        || rate_control.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP == 0
        || rate_control.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED != 0
    {
        return Ok(None);
    }
    // SAFETY: the hard-cap mode without weight-based control is the mode that
    // reads `CpuRate`, and this call verified those flags on the queried value
    // before reading that union arm.
    let cycles_per_10_000 = unsafe { rate_control.Anonymous.CpuRate };
    if cycles_per_10_000 == 0 || cycles_per_10_000 % 100 != 0 {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let percent =
        u16::try_from(cycles_per_10_000 / 100).map_err(|_| WindowsAdapterError::InvalidInput)?;
    Ok(Some(percent))
}

/// Attests one launch against the exact outer Job that launch will use.
///
/// The cached [`JobLaunchContainment`] verdict is necessary but not sufficient.
/// It is platform capability for the supported build, observed on temporary
/// probe Job Objects, so it is reused as such; it cannot speak about the Job a
/// particular launch presents. This adds the two per-launch facts the cached
/// verdict cannot supply:
///
/// 1. The verdict is bound to the identity of the outer Job that was actually
///    reopened for this launch. Two launches may share one build-level verdict
///    and must still be decided by their own Job Object.
/// 2. That outer Job itself carries kill-on-close. `I1.6` requires that "the
///    process tree receives kill-on-close at its outer ownership boundary", so
///    an outer Job without the flag would let this launch's descendants outlive
///    their kill domain. Only the flag is compared here: this Job is owned and
///    configured by the Host, so its resource ceilings are the Host's own
///    admitted values and not this launch's Module Manifest ceilings, which
///    belong to the nested per-attempt Job this launch creates.
///
/// A launch whose outer Job cannot be attested fails closed here. That failure
/// is this launch only: it is a typed adapter error returned from the launch
/// API, so the caller degrades to an unavailable launch and no sibling launch,
/// Host contour, or Watchdog branch is touched.
///
/// # Errors
/// Returns `Unavailable` when this build's containment verdict is missing or
/// the outer Job cannot be queried for its limits, and `IdentityMismatch` when
/// the verdict was not observed for this domain, was not contrasted against a
/// different domain, or the observed outer Job does not carry kill-on-close.
#[cfg(windows)]
fn require_attested_outer_job(
    outer_kill_domain: OuterKillDomain,
    outer_job: &RecoverableJobObject,
) -> Result<(), WindowsAdapterError> {
    let containment = probe_launch_containment(outer_kill_domain)?;
    if containment.domain() != outer_kill_domain
        || containment.distinct_domain() == outer_kill_domain
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    // Platform capability: this build nests and honours kill-on-close. It is
    // build-scoped evidence only, and on its own it never permits a launch.
    if !observed_job_containment(outer_job.handle.0)?.kill_on_close() {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(())
}

/// Attests the outer Job Object a launch has just created, before any child of
/// that launch exists.
///
/// This is the `spawn_named_host_outer_kill_domain` half of the same rule
/// [`require_attested_outer_job`] enforces for a reopened Host-owned outer Job:
/// the Job this launch created must be observed to carry kill-on-close and the
/// admitted ceilings, because a Job Object whose limit configuration was
/// rejected or replaced by another owner of the name would let the process tree
/// outlive its kill domain. Failing here returns before `CreateProcess`, so the
/// launch is refused with no child left behind.
///
/// # Errors
/// Returns `Unavailable` when Windows will not answer the limit query, and
/// `IdentityMismatch` when the created Job does not belong to `domain`, or does
/// not carry kill-on-close with the admitted ceilings.
#[cfg(windows)]
fn attest_created_outer_job(
    job: &JobObject,
    domain: OuterKillDomain,
    admitted_limits: JobObjectLimits,
) -> Result<(), WindowsAdapterError> {
    if job.outer_kill_domain() != Some(domain) {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let observed = observed_job_containment(job.handle)?;
    if !observed.kill_on_close() {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    if observed.limits() != &admitted_limits {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(())
}

/// Runs the real containment experiment for one kill domain.
#[cfg(windows)]
fn observe_launch_containment(
    domain: OuterKillDomain,
) -> Result<JobLaunchContainment, WindowsAdapterError> {
    use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    let distinct_domain = domain.contrasting_domain();
    let image = std::env::current_exe().map_err(|error| windows_adapter_from_io(&error))?;
    let working_directory = image
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(WindowsAdapterError::InvalidInput)?
        .to_path_buf();

    // The two outer Job Objects are real Host-owned outer kill domain Job
    // Objects of distinct domains, and the third is a per-generation Job
    // Object that deliberately carries no outer kill domain.
    let mut domain_job = JobObject::new_named_outer_kill_on_close_with_limits(
        domain,
        probe_outer_job_identity(domain)?,
        JobObjectLimits::default(),
    )?;
    let distinct_job = JobObject::new_named_outer_kill_on_close_with_limits(
        distinct_domain,
        probe_outer_job_identity(distinct_domain)?,
        JobObjectLimits::default(),
    )?;
    let nested_job = JobObject::new_named_kill_on_close_with_limits(
        probe_nested_job_identity()?,
        JobObjectLimits::default(),
    )?;
    if domain_job.outer_kill_domain() != Some(domain)
        || distinct_job.outer_kill_domain() != Some(distinct_domain)
        || nested_job.outer_kill_domain().is_some()
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }

    // Each guard stays armed for the whole experiment and stays bound for its
    // whole scope: it terminates and reaps its child even when the probe
    // returns an error early.
    let (domain_child, _domain_child_guard) =
        spawn_suspended_probe_child(&image, &working_directory)?;
    let (distinct_child, _distinct_child_guard) =
        spawn_suspended_probe_child(&image, &working_directory)?;

    // Assignment: the child has to actually be a member of the intended outer
    // Job Object before anything else may be claimed.
    domain_job.assign_process_handle(domain_child.0)?;
    if !is_process_in_job(domain_child.0, domain_job.handle)? {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    // Permitted nesting: a per-generation/per-attempt Job Object has to accept
    // a process that is already inside the outer Job Object, and the child has
    // to remain a member of both. A rejected or ineffective nested assignment
    // means this build cannot establish the required containment, so it fails
    // closed instead of silently degrading the limits or kill domain.
    if nested_job.assign_process_handle(domain_child.0).is_err() {
        return Err(WindowsAdapterError::Unavailable);
    }
    if !is_process_in_job(domain_child.0, nested_job.handle)? {
        return Err(WindowsAdapterError::Unavailable);
    }
    if !is_process_in_job(domain_child.0, domain_job.handle)? {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    distinct_job.assign_process_handle(distinct_child.0)?;
    if !is_process_in_job(distinct_child.0, distinct_job.handle)? {
        return Err(WindowsAdapterError::IdentityMismatch);
    }

    // Outer kill-on-close has to still govern: releasing the sole owning
    // handle of the outer Job Object must terminate the nested descendant,
    // even though the nested Job Object is still open.
    domain_job.close_owning_handle()?;
    if unsafe { WaitForSingleObject(domain_child.0, 5_000) } != WAIT_OBJECT_0 {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    // The other kill domain must be untouched by that close.
    if unsafe { WaitForSingleObject(distinct_child.0, 0) } != WAIT_TIMEOUT {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(JobLaunchContainment {
        domain,
        distinct_domain,
    })
}

/// Builds the unique Host-owned outer Job Object name one containment probe
/// uses for `domain`. The name is process- and sequence-scoped, so a probe can
/// never collide with the live Host Job Object of the same domain.
#[cfg(windows)]
fn probe_outer_job_identity(
    domain: OuterKillDomain,
) -> Result<JobObjectIdentity, WindowsAdapterError> {
    let sequence = JOB_OBJECT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    JobObjectIdentity::new(format!(
        "Local\\Eliot-Host-{}-probe-{}-{sequence}",
        domain.label(),
        std::process::id()
    ))
}

/// Builds the unique per-generation Job Object name one containment probe uses.
/// It is deliberately not a Host-owned outer name: nesting must never mint a
/// second outer kill domain.
#[cfg(windows)]
fn probe_nested_job_identity() -> Result<JobObjectIdentity, WindowsAdapterError> {
    let sequence = JOB_OBJECT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    JobObjectIdentity::new(format!(
        "Local\\Eliot-P02-probe-nested-{}-{sequence}",
        std::process::id()
    ))
}

/// Creates one suspended, never-resumed child of the current image and returns
/// its owned process handle plus an armed cleanup guard.
///
/// The child runs no instruction before the probe terminates it, so it can only
/// leave the suspended state by being terminated. That is what makes the
/// kill-on-close observation below unambiguous, and the guard terminates and
/// reaps the child even when the probe returns early.
#[cfg(windows)]
fn spawn_suspended_probe_child(
    image: &Path,
    working_directory: &Path,
) -> Result<(OwnedProcessHandle, SuspendedProcessCleanup), WindowsAdapterError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW,
    };
    let application =
        nul_terminated_wide(image.as_os_str()).map_err(|error| windows_adapter_from_io(&error))?;
    let mut command_line =
        command_line(image, &[]).map_err(|error| windows_adapter_from_io(&error))?;
    let current_directory = nul_terminated_wide(working_directory.as_os_str())
        .map_err(|error| windows_adapter_from_io(&error))?;
    let mut startup = STARTUPINFOW {
        cb: u32::try_from(std::mem::size_of::<STARTUPINFOW>())
            .map_err(|_| WindowsAdapterError::Failed)?,
        ..Default::default()
    };
    let mut information = PROCESS_INFORMATION::default();
    // SAFETY: every buffer stays live for the call, no handle is inherited, and
    // the child is created suspended so it executes nothing before the probe
    // observes or terminates it.
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            std::ptr::null_mut(),
            current_directory.as_ptr(),
            &raw mut startup,
            &raw mut information,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }
    if !information.hThread.is_null() {
        // SAFETY: `CreateProcessW` returned a fresh primary thread handle here.
        unsafe { CloseHandle(information.hThread) };
    }
    let process = OwnedProcessHandle::new(information.hProcess)?;
    let raw_process = process.0;
    Ok((
        process,
        SuspendedProcessCleanup {
            process: raw_process,
            armed: true,
        },
    ))
}

/// Reports whether `process` is a member of `job`. A null `job` asks whether
/// the process is inside any Job Object at all, which is the aggregate the
/// kernel exposes for a process inside a nested Job chain.
#[cfg(windows)]
fn is_process_in_job(
    process: windows_sys::Win32::Foundation::HANDLE,
    job: windows_sys::Win32::Foundation::HANDLE,
) -> Result<bool, WindowsAdapterError> {
    use windows_sys::Win32::System::JobObjects::IsProcessInJob;
    let mut member = 0;
    // SAFETY: both handles are live owned handles and `member` is a live out
    // pointer for the exact documented `BOOL`.
    if unsafe { IsProcessInJob(process, job, &raw mut member) } == 0 {
        Err(last_windows_adapter_error())
    } else {
        Ok(member != 0)
    }
}

/// Handle to an existing named Job Object during restart reconciliation.
///
/// Reopening proves only current kernel membership. Historical descendants
/// must be unioned with the caller-owned durable raw-observation ledger; this
/// type intentionally exposes no `complete` history claim.
#[cfg(windows)]
pub struct RecoverableJobObject {
    handle: OwnedKernelHandle,
    binding: RecoverableJobBinding,
}

#[cfg(windows)]
impl RecoverableJobObject {
    /// Opens one existing named Job with query and terminate access.
    ///
    /// # Errors
    /// Returns `NotFound` when kill-on-close already removed the Job, or a
    /// typed access/platform error otherwise.
    pub fn open(binding: RecoverableJobBinding) -> Result<Self, WindowsAdapterError> {
        const JOB_OBJECT_QUERY_ACCESS: u32 = 0x0004;
        const JOB_OBJECT_TERMINATE_ACCESS: u32 = 0x0008;
        const JOB_OBJECT_ASSIGN_PROCESS_ACCESS: u32 = 0x0001;
        use windows_sys::Win32::System::JobObjects::OpenJobObjectW;
        binding.validate()?;
        let name = nul_terminated_wide(std::ffi::OsStr::new(binding.job_identity().name()))
            .map_err(|error| windows_adapter_from_io(&error))?;
        // SAFETY: name is NUL-terminated and the call returns a new handle.
        let handle = unsafe {
            OpenJobObjectW(
                JOB_OBJECT_QUERY_ACCESS
                    | JOB_OBJECT_TERMINATE_ACCESS
                    | JOB_OBJECT_ASSIGN_PROCESS_ACCESS,
                0,
                name.as_ptr(),
            )
        };
        if handle.is_null() {
            let error = std::io::Error::last_os_error();
            if matches!(error.kind(), std::io::ErrorKind::NotFound) {
                return Err(WindowsAdapterError::NotFound);
            }
            return Err(windows_adapter_from_io(&error));
        }
        let recovered = Self {
            handle: OwnedKernelHandle::new(handle)?,
            binding,
        };
        let live = recovered.live_processes()?;
        if !live
            .iter()
            .any(|process| process == recovered.binding.root())
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(recovered)
    }

    /// Returns the exact Job identity used to reopen the object.
    #[must_use]
    pub const fn identity(&self) -> &JobObjectIdentity {
        self.binding.job_identity()
    }

    /// Returns the durable binding revalidated when this handle was opened.
    #[must_use]
    pub const fn binding(&self) -> &RecoverableJobBinding {
        &self.binding
    }

    /// Returns current live members with PID-reuse-safe process/image identity.
    ///
    /// # Errors
    /// Returns a typed adapter error when membership or identity cannot be read.
    pub fn live_processes(&self) -> Result<Vec<ProcessObservation>, WindowsAdapterError> {
        job_process_ids(self.handle.0)
            .map_err(|error| windows_adapter_from_io(&error))?
            .into_iter()
            .map(open_observed_job_process)
            .map(|result| result.map(|process| process.observation))
            .collect()
    }

    /// Returns the current active member count.
    ///
    /// # Errors
    /// Returns a typed adapter error when the Job cannot be queried.
    pub fn active_process_count(&self) -> Result<u32, WindowsAdapterError> {
        u32::try_from(
            job_process_ids(self.handle.0)
                .map_err(|error| windows_adapter_from_io(&error))?
                .len(),
        )
        .map_err(|_| WindowsAdapterError::Failed)
    }

    #[cfg(windows)]
    fn assign_process_handle(
        &self,
        process: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), WindowsAdapterError> {
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        if unsafe { AssignProcessToJobObject(self.handle.0, process) } == 0 {
            Err(last_windows_adapter_error())
        } else {
            Ok(())
        }
    }

    #[cfg(windows)]
    fn contains_process(&self, process_id: u32) -> Result<bool, WindowsAdapterError> {
        job_process_ids(self.handle.0)
            .map(|processes| processes.into_iter().any(|pid| pid == process_id))
            .map_err(|error| windows_adapter_from_io(&error))
    }

    /// Terminates all current members.
    ///
    /// # Errors
    /// Returns a typed adapter error when Windows rejects termination.
    pub fn terminate(&self, exit_code: u32) -> Result<(), WindowsAdapterError> {
        // SAFETY: the reopened Job handle remains live for the call.
        if unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.handle.0, exit_code)
        } == 0
        {
            Err(last_windows_adapter_error())
        } else {
            Ok(())
        }
    }

    /// Waits until no live member remains.
    ///
    /// # Errors
    /// Returns a typed adapter error when current membership cannot be read.
    pub fn wait_for_empty(
        &self,
        timeout: std::time::Duration,
    ) -> Result<bool, WindowsAdapterError> {
        let started = std::time::Instant::now();
        loop {
            if self.active_process_count()? == 0 {
                return Ok(true);
            }
            if started.elapsed() >= timeout {
                return Ok(false);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// Launches one validated child into this already-open Job Object.
    ///
    /// The returned typestate borrows this recovery handle for its whole
    /// lifetime. It therefore cannot outlive the shared Job owner and never
    /// owns, closes, or terminates that Job. Only the new process is owned by
    /// the member typestate.
    ///
    /// # Errors
    /// Returns a typed adapter error when the retained root is no longer a
    /// member, launch material is invalid, assignment fails, or exact member
    /// identity cannot be observed before publication.
    pub fn spawn_member(
        &self,
        spec: SuspendedLaunchSpec,
    ) -> Result<SuspendedExistingJobChild<'_>, WindowsAdapterError> {
        if spec.retain_stdin_writer {
            return Err(WindowsAdapterError::InvalidInput);
        }
        if !self
            .live_processes()?
            .iter()
            .any(|process| process == self.binding.root())
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        spawn_existing_job_member(self, spec)
    }
}

#[cfg(windows)]
struct SuspendedProcessCleanup {
    process: windows_sys::Win32::Foundation::HANDLE,
    armed: bool,
}

#[cfg(windows)]
impl SuspendedProcessCleanup {
    fn disarm(&mut self) {
        self.armed = false;
    }

    fn terminate_and_reap(&mut self) -> bool {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};

        if !self.armed || self.process.is_null() {
            return false;
        }
        let _ = unsafe { TerminateProcess(self.process, 0xE1_04) };
        if unsafe { WaitForSingleObject(self.process, 5_000) } == WAIT_OBJECT_0 {
            self.armed = false;
            true
        } else {
            false
        }
    }
}

#[cfg(windows)]
impl Drop for SuspendedProcessCleanup {
    fn drop(&mut self) {
        let _ = self.terminate_and_reap();
    }
}

#[cfg(windows)]
fn cleanup_error(
    cleanup: &mut SuspendedProcessCleanup,
    original: WindowsAdapterError,
) -> WindowsAdapterError {
    if cleanup.terminate_and_reap() {
        original
    } else {
        WindowsAdapterError::Timeout
    }
}

/// Read-pinned protected runtime input retained while a Host contour is
/// running. The no-follow handle prevents replacement or reparse substitution
/// after digest verification.
#[cfg(windows)]
pub struct PinnedRuntimeFile {
    _file: PinnedExecutable,
}

#[cfg(windows)]
impl PinnedRuntimeFile {
    /// Opens one regular non-reparse runtime input with replacement-blocking
    /// sharing semantics.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is not a regular absolute file, crosses
    /// a reparse point, or cannot be opened with replacement-blocking sharing.
    pub fn open(path: &Path) -> Result<Self, WindowsAdapterError> {
        Ok(Self {
            _file: PinnedExecutable::open(path)?,
        })
    }
}

/// Upper bound for the single standard-input payload one suspended launch may
/// carry.
///
/// The child is still suspended when the parent writes the payload, so nothing
/// is draining the pipe yet: a payload larger than the pipe buffer would block
/// the spawning thread forever with no reader. [`stdin_pipe_buffer_bytes`]
/// therefore sizes the pipe this launch uses, and this ceiling stays far below
/// that size, so a conforming payload is always accepted whole without blocking.
/// An over-limit payload is refused here rather than deadlocking the spawn.
/// This is a mechanics bound, not a policy: what an admitted launch may put on
/// the wire is decided by its own owner.
#[cfg(windows)]
pub const SUSPENDED_LAUNCH_STDIN_LIMIT: usize = 8 * 1024;

/// Reserved capacity of the standard-input pipe of a launch that carries a
/// payload.
///
/// A zero size would leave the pipe at the system default, which for an
/// anonymous pipe is small enough that a realistic one-shot request line could
/// not be written before the child is resumed. The reservation is paid only by
/// the launches that actually carry a payload; a launch without one still asks
/// for the default buffer, so its previous behaviour is unchanged.
#[cfg(windows)]
const STDIN_PAYLOAD_PIPE_BUFFER_BYTES: u32 = 64 * 1024;

/// Returns the reserved standard-input pipe capacity for this launch.
///
/// `0` means "system default" and is what a launch without a payload gets, so
/// that path is byte-for-byte the previous behaviour.
#[cfg(windows)]
fn stdin_pipe_buffer_bytes(spec: &SuspendedLaunchSpec) -> u32 {
    if spec.stdin_payload.is_some() {
        STDIN_PAYLOAD_PIPE_BUFFER_BYTES
    } else {
        0
    }
}

/// Identity a launch declares for the child it is about to create.
///
/// `I1.6` requires that "`system_service` uses a dedicated low-privilege
/// service identity; `user_mode` runs under the current user without pretending
/// to be an SCM service". This is the selection that clause asks for: the launch
/// names which of those two identities it is, and process creation then uses
/// exactly that identity's token rather than whichever token the caller happens
/// to hold.
///
/// This is deliberately not the WorkScope execution-identity vocabulary. `I1.6`
/// declares `service`/`interactive_user:<sid>`/`remote` per WorkScope resource in
/// a different subsection; those name *what a resource may reach*, whereas this
/// names *which token this one child process is created with*, and reusing the
/// resource-level words here would let a resource declaration silently stand in
/// for the identity the process actually runs under.
#[cfg(windows)]
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionIdentityMode {
    /// The dedicated low-privilege service identity, selected from the machine
    /// by this launch rather than inherited from the caller.
    ///
    /// If this token cannot be obtained the launch is refused. It never degrades
    /// to the caller's own identity.
    SystemService,
    /// The current user's own token, with no SCM service semantics attached.
    UserMode,
}

impl ExecutionIdentityMode {
    /// Reports whether this mode is declared under the current user's identity.
    #[must_use]
    pub const fn is_user_mode(self) -> bool {
        matches!(self, Self::UserMode)
    }
}

/// Resolves the token this declared mode creates the child with, together with
/// the exact SID and session the child's token must be observed to carry once it
/// starts.
///
/// `CreateProcessW` has no token parameter, so a launch that names an identity
/// cannot use it: it needs `CreateProcessAsUserW` with an explicitly chosen
/// primary token. Both modes therefore resolve a token here, so the identity is
/// an explicit input to process creation in both cases rather than an implicit
/// inheritance in one of them.
///
/// `UserMode` duplicates the current process token as a primary token, which is
/// the same identity `CreateProcessW` would have inherited, but is now passed
/// explicitly. `SystemService` opens the dedicated low-privilege service token.
///
/// A `UserMode` launch performed by one of the built-in service accounts is
/// refused: there is no current *user* there, and creating the child from that
/// token would be the SCM pretence `I1.6` forbids.
///
/// # Errors
/// Returns `Unavailable` when the declared mode's token cannot be obtained, and
/// `IdentityMismatch` when a `UserMode` launch is attempted from a built-in
/// service account. There is no fallback to the current token in either case.
#[cfg(windows)]
fn resolve_execution_identity_token(
    mode: ExecutionIdentityMode,
) -> Result<SelectedExecutionToken, WindowsAdapterError> {
    use crate::process_identity::{
        is_well_known_service_account_sid, open_dedicated_low_privilege_service_token,
        token_identity,
    };
    use windows_sys::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
        TokenPrimary,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    if mode == ExecutionIdentityMode::SystemService {
        let token = open_dedicated_low_privilege_service_token()?;
        // The expected session is read from the selected token itself rather
        // than assumed, so the later read-back compares the child against what
        // this token actually carries.
        let (expected_sid, expected_session_id) = token_identity(token.0)?;
        return Ok(SelectedExecutionToken {
            mode,
            token,
            expected_sid,
            expected_session_id,
        });
    }

    let current_process = unsafe { GetCurrentProcess() };
    let (sid, session_id) = crate::process_token_identity(current_process)?;
    if is_well_known_service_account_sid(&sid) {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let mut source = std::ptr::null_mut();
    // SAFETY: the current process pseudo-handle is always valid and `source`
    // is a valid output pointer.
    if unsafe {
        OpenProcessToken(
            current_process,
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY,
            &raw mut source,
        )
    } == 0
    {
        return Err(WindowsAdapterError::Unavailable);
    }
    let mut primary = std::ptr::null_mut();
    // SAFETY: `source` is a live token handle just opened by `OpenProcessToken`,
    // and `primary` is a valid output pointer. A primary token is required
    // because `CreateProcessAsUserW` cannot create from an impersonation token.
    let duplicated = unsafe {
        DuplicateTokenEx(
            source,
            TOKEN_IMPERSONATE | TOKEN_QUERY,
            std::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &raw mut primary,
        )
    };
    // SAFETY: `source` is a live owned handle this scope no longer needs.
    unsafe { windows_sys::Win32::Foundation::CloseHandle(source) };
    if duplicated == 0 {
        return Err(WindowsAdapterError::Unavailable);
    }
    let Ok(token) = OwnedProcessHandle::new(primary) else {
        // SAFETY: `primary` is a live owned handle `OwnedProcessHandle` just
        // refused to wrap, so nothing else owns it.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(primary) };
        return Err(WindowsAdapterError::Unavailable);
    };
    Ok(SelectedExecutionToken {
        mode,
        token,
        expected_sid: sid,
        expected_session_id: session_id,
    })
}

/// The token one launch creates its child with, and the identity that child must
/// then be observed to carry.
///
/// Holding both together is what makes the read-back meaningful: the expected
/// SID is captured at the moment the token was selected, not recomputed from the
/// same code path that would observe it.
#[cfg(windows)]
struct SelectedExecutionToken {
    mode: ExecutionIdentityMode,
    token: OwnedProcessHandle,
    expected_sid: String,
    expected_session_id: u32,
}

/// Complete deterministic input to the Windows suspended-launch primitive.
///
/// This value contains mechanics only. It is not a dispatch permit and carries
/// no authority. Environment inheritance is intentionally unavailable: callers
/// must supply the complete child environment explicitly.
///
/// The standard-input payload is optional and absent by default, so a launch
/// that needs no input keeps exactly the previous four-field behaviour: the
/// pipe is created, never written, and closed.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuspendedLaunchSpec {
    executable: PathBuf,
    arguments: Vec<std::ffi::OsString>,
    working_directory: PathBuf,
    environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    stdin_payload: Option<Vec<u8>>,
    retain_stdin_writer: bool,
    execution_identity: ExecutionIdentityMode,
}

#[cfg(windows)]
impl SuspendedLaunchSpec {
    /// Creates a deterministic launch specification without granting authority.
    ///
    /// # Errors
    /// Returns `InvalidInput` unless the executable and working directory are
    /// absolute existing paths and all argument/environment material is valid
    /// Windows UTF-16 without duplicate case-insensitive environment names.
    pub fn new(
        executable: impl Into<PathBuf>,
        arguments: Vec<std::ffi::OsString>,
        working_directory: impl Into<PathBuf>,
        environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    ) -> Result<Self, WindowsAdapterError> {
        let executable = executable.into();
        let working_directory = working_directory.into();
        if !executable.is_absolute()
            || !executable.is_file()
            || !working_directory.is_absolute()
            || !working_directory.is_dir()
            || os_has_nul(executable.as_os_str())
            || os_has_nul(working_directory.as_os_str())
            || arguments.iter().any(|argument| os_has_nul(argument))
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        validate_complete_environment(&environment)?;
        Ok(Self {
            executable,
            arguments,
            working_directory,
            environment,
            stdin_payload: None,
            retain_stdin_writer: false,
            execution_identity: ExecutionIdentityMode::UserMode,
        })
    }

    /// Declares the identity this launch creates its child under.
    ///
    /// `UserMode` is the default because it is the identity the launching
    /// process already holds, which keeps every existing launch spec behaving
    /// exactly as before. `SystemService` is the only other selection, and it
    /// never falls back to the caller: a launch that selects it and cannot
    /// obtain the dedicated low-privilege service token is unavailable.
    #[must_use]
    pub fn with_execution_identity(mut self, execution_identity: ExecutionIdentityMode) -> Self {
        self.execution_identity = execution_identity;
        self
    }

    /// Returns the exact identity this launch declared for its child.
    #[must_use]
    pub const fn execution_identity(&self) -> ExecutionIdentityMode {
        self.execution_identity
    }

    /// Attaches the exact one-shot standard-input bytes this launch hands the
    /// child.
    ///
    /// The bytes are written to the child's standard input and the sole parent
    /// writer is closed immediately afterwards, so the child reads exactly
    /// these bytes and then observes deterministic EOF instead of inherited
    /// console input or a writer that never closes. This is the only channel
    /// by which a per-user one-shot adapter receives its request line
    /// (I11.6:3, "Normal delivery is launched through the authorized User
    /// Broker").
    ///
    /// `None` is the default and keeps the previous behaviour exactly: the
    /// pipe is created, never written, and closed.
    ///
    /// # Errors
    /// Returns `InvalidInput` for an empty or over-limit payload, and never
    /// accepts one the suspended child could not drain before the parent
    /// closed its writer.
    pub fn with_stdin(mut self, payload: Vec<u8>) -> Result<Self, WindowsAdapterError> {
        if self.retain_stdin_writer
            || payload.is_empty()
            || payload.len() > SUSPENDED_LAUNCH_STDIN_LIMIT
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        self.stdin_payload = Some(payload);
        Ok(self)
    }

    /// Retains the parent's standard-input writer for frames sent after the
    /// child resumes. The writer is transferred with the running child and
    /// remains open until its owner closes the child lifecycle.
    ///
    /// This mode carries no launch or protocol authority. Callers provide
    /// already-framed bytes through their admitted operation owner. It cannot
    /// be combined with [`Self::with_stdin`], whose bytes are delivered before
    /// resume and followed by EOF.
    ///
    /// # Errors
    /// Returns `InvalidInput` if one-shot input is already attached or this
    /// live-writer mode was already selected.
    pub fn with_live_stdin(mut self) -> Result<Self, WindowsAdapterError> {
        if self.retain_stdin_writer || self.stdin_payload.is_some() {
            return Err(WindowsAdapterError::InvalidInput);
        }
        self.retain_stdin_writer = true;
        Ok(self)
    }

    /// Returns the exact one-shot standard-input bytes, if this launch carries
    /// them.
    #[must_use]
    pub fn stdin_payload(&self) -> Option<&[u8]> {
        self.stdin_payload.as_deref()
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    #[must_use]
    pub fn arguments(&self) -> &[std::ffi::OsString] {
        &self.arguments
    }

    #[must_use]
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    #[must_use]
    pub fn environment(&self) -> &[(std::ffi::OsString, std::ffi::OsString)] {
        &self.environment
    }
}

/// Fresh mechanics evidence observed while the process is still suspended.
///
/// This type is deliberately non-serializable and non-cloneable. It is never
/// an authority receipt; only the caller-provided validator can return the
/// opaque validation token required by the next typestate.
#[cfg(windows)]
pub struct SuspendedProcessEvidence {
    process: ProcessIdentity,
    executable: FileIdentity,
    job: JobObjectIdentity,
    requested_executable: PathBuf,
    arguments: Vec<std::ffi::OsString>,
    working_directory: PathBuf,
    environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    command_line_utf16: Vec<u16>,
    job_process_count: u32,
    enforced_limits: Option<JobObjectLimits>,
}

#[cfg(windows)]
impl SuspendedProcessEvidence {
    #[must_use]
    pub fn process(&self) -> &ProcessIdentity {
        &self.process
    }

    #[must_use]
    pub const fn executable_file_identity(&self) -> FileIdentity {
        self.executable
    }

    /// Returns the fresh, owner-scoped Job Object identity.
    #[must_use]
    pub const fn job_identity(&self) -> &JobObjectIdentity {
        &self.job
    }

    /// Builds the raw durable binding required for later named-Job recovery.
    #[must_use]
    pub fn recoverable_job_binding(&self) -> RecoverableJobBinding {
        RecoverableJobBinding {
            job: self.job.clone(),
            root: ProcessObservation {
                process: self.process.clone(),
                executable: self.executable,
            },
        }
    }

    #[must_use]
    pub fn requested_executable(&self) -> &Path {
        &self.requested_executable
    }

    #[must_use]
    pub fn arguments(&self) -> &[std::ffi::OsString] {
        &self.arguments
    }

    #[must_use]
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    #[must_use]
    pub fn environment(&self) -> &[(std::ffi::OsString, std::ffi::OsString)] {
        &self.environment
    }

    #[must_use]
    pub fn command_line_utf16(&self) -> &[u16] {
        &self.command_line_utf16
    }

    #[must_use]
    pub const fn job_process_count(&self) -> u32 {
        self.job_process_count
    }

    /// Returns the exact resource ceilings installed on the containing Job
    /// before any process was assigned, bound to this admitted identity.
    ///
    /// Fresh contained spawns report `Some` with the ceilings passed to the
    /// limit constructor. Members launched into a reopened Job report `None`:
    /// the enforced ceilings of a pre-existing Job are unknown to this launch
    /// and are explicit here, never zero or a containment claim.
    #[must_use]
    pub const fn enforced_limits(&self) -> Option<JobObjectLimits> {
        self.enforced_limits
    }
}

/// Failure of the consuming caller-owned validation transition.
#[cfg(windows)]
#[derive(Debug, Eq, PartialEq)]
pub enum SuspendedValidationError<E> {
    Mechanics(WindowsAdapterError),
    Rejected(E),
    /// Cleanup could not observe that the still-suspended child was reaped.
    UnknownOutcome,
}

#[cfg(windows)]
const JOB_COMPLETION_KEY: usize = 0x454c_494f;
#[cfg(windows)]
const JOB_OBSERVER_SHUTDOWN_KEY: usize = 0x454e_4421;
#[cfg(windows)]
const JOB_OBJECT_MSG_END_OF_JOB_TIME: u32 = 1;
#[cfg(windows)]
const JOB_OBJECT_MSG_END_OF_PROCESS_TIME: u32 = 2;
#[cfg(windows)]
const JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT: u32 = 3;
#[cfg(windows)]
const JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO: u32 = 4;
#[cfg(windows)]
const JOB_OBJECT_MSG_NEW_PROCESS: u32 = 6;
#[cfg(windows)]
const JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT: u32 = 9;
#[cfg(windows)]
const JOB_OBJECT_MSG_JOB_MEMORY_LIMIT: u32 = 10;

#[cfg(windows)]
struct ObservedJobProcess {
    observation: ProcessObservation,
    _process: OwnedProcessHandle,
    _executable: PinnedExecutable,
}

#[cfg(windows)]
#[derive(Default)]
struct JobProcessObserverState {
    processes: Vec<ObservedJobProcess>,
    observation_incomplete: bool,
    active_process_zero: bool,
    resource_limit_triggered: bool,
}

#[cfg(windows)]
struct JobProcessObserver {
    completion_port: OwnedKernelHandle,
    state: std::sync::Arc<(
        std::sync::Mutex<JobProcessObserverState>,
        std::sync::Condvar,
    )>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(windows)]
impl JobProcessObserver {
    fn attach(job: windows_sys::Win32::Foundation::HANDLE) -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::IO::CreateIoCompletionPort;
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JobObjectAssociateCompletionPortInformation,
            SetInformationJobObject,
        };
        // SAFETY: this documented form creates one standalone completion port.
        let completion_port =
            unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, std::ptr::null_mut(), 0, 1) };
        let completion_port = OwnedKernelHandle::new(completion_port)?;
        let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: JOB_COMPLETION_KEY as *mut std::ffi::c_void,
            CompletionPort: completion_port.0,
        };
        let length = u32::try_from(std::mem::size_of_val(&association))
            .map_err(|_| WindowsAdapterError::Failed)?;
        // SAFETY: both handles and the exact association structure are live.
        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectAssociateCompletionPortInformation,
                (&raw const association).cast(),
                length,
            )
        } == 0
        {
            return Err(last_windows_adapter_error());
        }
        let state = std::sync::Arc::new((
            std::sync::Mutex::new(JobProcessObserverState::default()),
            std::sync::Condvar::new(),
        ));
        let thread_state = std::sync::Arc::clone(&state);
        let raw_port = completion_port.0 as usize;
        let thread = std::thread::Builder::new()
            .name("eliot-p02-job-observer".to_owned())
            .spawn(move || job_process_observer_loop(raw_port, &thread_state))
            .map_err(|error| windows_adapter_from_io(&error))?;
        Ok(Self {
            completion_port,
            state,
            thread: Some(thread),
        })
    }

    fn capture_pid(&self, process_id: u32) -> Result<(), WindowsAdapterError> {
        let process = open_observed_job_process(process_id)?;
        let (state, _) = &*self.state;
        let mut state = state.lock().map_err(|_| WindowsAdapterError::Failed)?;
        if !state
            .processes
            .iter()
            .any(|observed| observed.observation == process.observation)
        {
            state.processes.push(process);
        }
        Ok(())
    }

    fn capture_live_members(
        &self,
        job: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<bool, WindowsAdapterError> {
        let process_ids = job_process_ids(job).map_err(|error| windows_adapter_from_io(&error))?;
        for process_id in &process_ids {
            if self.capture_pid(*process_id).is_err() {
                let (state, _) = &*self.state;
                let mut state = state.lock().map_err(|_| WindowsAdapterError::Failed)?;
                state.observation_incomplete = true;
            }
        }
        Ok(process_ids.is_empty())
    }

    fn snapshot(
        &self,
        job: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<JobProcessHistory, WindowsAdapterError> {
        let job_empty = self.capture_live_members(job)?;
        self.snapshot_with_empty(job_empty)
    }

    fn wait_for_empty_history(
        &self,
        job: windows_sys::Win32::Foundation::HANDLE,
        timeout: std::time::Duration,
    ) -> Result<JobProcessHistory, WindowsAdapterError> {
        let started = std::time::Instant::now();
        loop {
            if self.capture_live_members(job)? {
                break;
            }
            if started.elapsed() >= timeout {
                return self.snapshot_with_empty(false);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let (state, notification) = &*self.state;
        let mut state = state.lock().map_err(|_| WindowsAdapterError::Failed)?;
        while !state.active_process_zero {
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                break;
            }
            let (next, wait) = notification
                .wait_timeout(state, remaining)
                .map_err(|_| WindowsAdapterError::Failed)?;
            state = next;
            if wait.timed_out() {
                break;
            }
        }
        Ok(history_from_observer_state(&state, true))
    }

    fn snapshot_with_empty(
        &self,
        job_empty: bool,
    ) -> Result<JobProcessHistory, WindowsAdapterError> {
        let (state, _) = &*self.state;
        let state = state.lock().map_err(|_| WindowsAdapterError::Failed)?;
        Ok(history_from_observer_state(&state, job_empty))
    }

    fn shutdown(&mut self) {
        use windows_sys::Win32::System::IO::PostQueuedCompletionStatus;

        if self.thread.is_none() {
            return;
        }
        // SAFETY: the port stays live until the observer thread is joined.
        let _ = unsafe {
            PostQueuedCompletionStatus(
                self.completion_port.0,
                0,
                JOB_OBSERVER_SHUTDOWN_KEY,
                std::ptr::null(),
            )
        };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(windows)]
impl Drop for JobProcessObserver {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(windows)]
fn history_from_observer_state(
    state: &JobProcessObserverState,
    job_empty: bool,
) -> JobProcessHistory {
    let mut processes = state
        .processes
        .iter()
        .map(|observed| observed.observation.clone())
        .collect::<Vec<_>>();
    processes.sort_by_key(ProcessObservation::stable_key);
    processes.dedup();
    JobProcessHistory {
        processes,
        complete: job_empty && state.active_process_zero && !state.observation_incomplete,
        job_empty,
        capture_gap: state
            .observation_incomplete
            .then_some(JobObservationGap::IdentityCaptureFailed),
        resource_limit_triggered: state.resource_limit_triggered,
    }
}

#[cfg(windows)]
fn open_observed_job_process(process_id: u32) -> Result<ObservedJobProcess, WindowsAdapterError> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    if process_id == 0 {
        return Err(WindowsAdapterError::InvalidInput);
    }
    // SAFETY: OpenProcess returns a newly owned handle or null.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    let process = OwnedProcessHandle::new(handle)?;
    let identity = inspect_process_handle(process_id, process.0)
        .map_err(|error| windows_adapter_from_io(&error))?;
    let executable = PinnedExecutable::open(Path::new(&identity.image_path))?;
    let observation = ProcessObservation {
        process: identity,
        executable: executable.identity,
    };
    Ok(ObservedJobProcess {
        observation,
        _process: process,
        _executable: executable,
    })
}

#[cfg(windows)]
fn job_process_observer_loop(
    raw_port: usize,
    shared: &std::sync::Arc<(
        std::sync::Mutex<JobProcessObserverState>,
        std::sync::Condvar,
    )>,
) {
    use windows_sys::Win32::System::IO::GetQueuedCompletionStatus;
    let completion_port = raw_port as windows_sys::Win32::Foundation::HANDLE;
    loop {
        let mut message = 0_u32;
        let mut completion_key = 0_usize;
        let mut overlapped = std::ptr::null_mut();
        // SAFETY: all out pointers are live and the observer owns the port.
        let dequeued = unsafe {
            GetQueuedCompletionStatus(
                completion_port,
                &raw mut message,
                &raw mut completion_key,
                &raw mut overlapped,
                u32::MAX,
            )
        };
        if completion_key == JOB_OBSERVER_SHUTDOWN_KEY {
            break;
        }
        if dequeued == 0 || completion_key != JOB_COMPLETION_KEY {
            continue;
        }
        let (state, notification) = &**shared;
        if message == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO {
            if let Ok(mut state) = state.lock() {
                state.active_process_zero = true;
                notification.notify_all();
            }
            continue;
        }
        if matches!(
            message,
            JOB_OBJECT_MSG_END_OF_JOB_TIME
                | JOB_OBJECT_MSG_END_OF_PROCESS_TIME
                | JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT
                | JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT
                | JOB_OBJECT_MSG_JOB_MEMORY_LIMIT
        ) {
            if let Ok(mut state) = state.lock() {
                state.resource_limit_triggered = true;
                notification.notify_all();
            }
            continue;
        }
        if message != JOB_OBJECT_MSG_NEW_PROCESS {
            continue;
        }
        let Ok(process_id) = u32::try_from(overlapped as usize) else {
            if let Ok(mut state) = state.lock() {
                state.observation_incomplete = true;
            }
            continue;
        };
        let observed = open_observed_job_process(process_id);
        if let Ok(mut state) = state.lock() {
            state.active_process_zero = false;
            match observed {
                Ok(process)
                    if !state
                        .processes
                        .iter()
                        .any(|existing| existing.observation == process.observation) =>
                {
                    state.processes.push(process);
                }
                Ok(_) => {}
                Err(_) => state.observation_incomplete = true,
            }
        }
    }
}

#[cfg(windows)]
struct ProcThreadAttributeList {
    _storage: Vec<usize>,
    list: windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST,
}

#[cfg(windows)]
impl ProcThreadAttributeList {
    fn for_inherited_handles(
        handles: &[windows_sys::Win32::Foundation::HANDLE],
    ) -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::System::Threading::{
            InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            UpdateProcThreadAttribute,
        };
        let mut bytes = 0_usize;
        // SAFETY: the documented sizing call writes only `bytes`.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &raw mut bytes);
        }
        if bytes == 0 {
            return Err(last_windows_adapter_error());
        }
        let words = bytes.div_ceil(std::mem::size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let list = storage.as_mut_ptr().cast::<std::ffi::c_void>();
        // SAFETY: storage is aligned, sufficiently large, and retained.
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &raw mut bytes) } == 0 {
            return Err(last_windows_adapter_error());
        }
        let attribute = usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
            .map_err(|_| WindowsAdapterError::Failed)?;
        // SAFETY: list and exact handle slice are live for this call.
        if unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                attribute,
                handles.as_ptr().cast::<std::ffi::c_void>(),
                std::mem::size_of_val(handles),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            let error = last_windows_adapter_error();
            // SAFETY: list was initialized above.
            unsafe {
                windows_sys::Win32::System::Threading::DeleteProcThreadAttributeList(list);
            }
            return Err(error);
        }
        Ok(Self {
            _storage: storage,
            list,
        })
    }
}

#[cfg(windows)]
impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        // SAFETY: list remains initialized and its storage is still live.
        unsafe {
            windows_sys::Win32::System::Threading::DeleteProcThreadAttributeList(self.list);
        }
    }
}

#[cfg(windows)]
fn inheritable_pipe() -> Result<(OwnedKernelHandle, OwnedKernelHandle), WindowsAdapterError> {
    inheritable_pipe_with_buffer(0)
}

/// Creates one inheritable anonymous pipe pair with an explicit reserved
/// capacity.
///
/// A `buffer_bytes` of `0` asks for the system default, which is the historical
/// behaviour of every launch. A non-zero value is used only by the standard
/// input of a launch that carries a one-shot payload, so that payload fits
/// before the suspended child is resumed (see [`stdin_pipe_buffer_bytes`]).
#[cfg(windows)]
fn inheritable_pipe_with_buffer(
    buffer_bytes: u32,
) -> Result<(OwnedKernelHandle, OwnedKernelHandle), WindowsAdapterError> {
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::CreatePipe;
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| WindowsAdapterError::Failed)?,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: output pointers and security attributes are valid for the call.
    if unsafe {
        CreatePipe(
            &raw mut read,
            &raw mut write,
            &raw const attributes,
            buffer_bytes,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }
    Ok((
        OwnedKernelHandle::new(read)?,
        OwnedKernelHandle::new(write)?,
    ))
}

#[cfg(windows)]
fn make_non_inheritable(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(), WindowsAdapterError> {
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    // SAFETY: the live handle is borrowed only for this call.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        Err(last_windows_adapter_error())
    } else {
        Ok(())
    }
}

/// Writes the launch's one-shot standard-input payload to the child's stdin
/// pipe.
///
/// Absent payload is a no-op, so a launch that needs no input keeps the exact
/// previous behaviour and the comment at the call sites stays true. A present
/// payload is written whole or not at all: an anonymous pipe `WriteFile` either
/// accepts all `nLength` bytes or fails, so a short write is treated as a
/// mechanics failure rather than a partial record the child would act on. The
/// write happens while the parent still holds the sole writer, and the caller
/// closes that writer immediately afterwards, so the child reads these exact
/// bytes and then observes deterministic EOF.
///
/// The caller must have already bounded the payload by
/// [`SUSPENDED_LAUNCH_STDIN_LIMIT`]: the child is still suspended here, so a
/// larger write would block the parent instead of returning.
#[cfg(windows)]
fn deliver_stdin_payload(
    writer: &OwnedKernelHandle,
    payload: Option<&[u8]>,
) -> Result<(), WindowsAdapterError> {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    let Some(payload) = payload else {
        return Ok(());
    };
    if payload.is_empty() || payload.len() > SUSPENDED_LAUNCH_STDIN_LIMIT {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let expected = u32::try_from(payload.len()).map_err(|_| WindowsAdapterError::InvalidInput)?;
    let mut written: u32 = 0;
    // SAFETY: `writer` is the live, non-inheritable write end of the child's
    // stdin pipe; `payload` is a live slice of exactly `expected` bytes;
    // `written` is a live exclusive local; a null OVERLAPPED requests the
    // synchronous call, so no event, iocp, or completion path is used.
    let accepted = unsafe {
        WriteFile(
            writer.0,
            payload.as_ptr(),
            expected,
            &raw mut written,
            std::ptr::null_mut(),
        )
    };
    if accepted == 0 {
        return Err(last_windows_adapter_error());
    }
    if written != expected {
        return Err(WindowsAdapterError::Failed);
    }
    Ok(())
}

#[cfg(windows)]
struct JobChildHandles {
    process: OwnedProcessHandle,
    thread: OwnedProcessHandle,
    job: JobObject,
    resource_limits: JobObjectLimits,
    spawn_identity: ProcessIdentity,
    executable: PinnedExecutable,
    spec: SuspendedLaunchSpec,
    command_line_utf16: Vec<u16>,
    stdin: Option<std::fs::File>,
    stdout: Option<std::fs::File>,
    stderr: Option<std::fs::File>,
    observer: JobProcessObserver,
    terminal: bool,
}

#[cfg(windows)]
impl JobChildHandles {
    fn fresh_evidence(&self) -> Result<SuspendedProcessEvidence, WindowsAdapterError> {
        use windows_sys::Win32::System::Threading::GetProcessId;
        let process_id = unsafe { GetProcessId(self.process.0) };
        if process_id == 0 || process_id != self.spawn_identity.process_id {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let process = inspect_process_handle(process_id, self.process.0)
            .map_err(|error| windows_adapter_from_io(&error))?;
        if process.start_time_100ns != self.spawn_identity.start_time_100ns
            || !same_windows_path(&process.image_path, &self.spawn_identity.image_path)
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let observed_file = file_identity(Path::new(&process.image_path))
            .map_err(|error| windows_adapter_from_io(&error))?;
        if observed_file != self.executable.identity || !self.job.contains_process(process_id)? {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let count = u32::try_from(
            job_process_ids(self.job.handle)
                .map_err(|error| windows_adapter_from_io(&error))?
                .len(),
        )
        .map_err(|_| WindowsAdapterError::Failed)?;
        if count == 0 {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(SuspendedProcessEvidence {
            process,
            executable: observed_file,
            job: self.job.identity().clone(),
            requested_executable: self.spec.executable.clone(),
            arguments: self.spec.arguments.clone(),
            working_directory: self.spec.working_directory.clone(),
            environment: self.spec.environment.clone(),
            command_line_utf16: self.command_line_utf16.clone(),
            job_process_count: count,
            enforced_limits: Some(self.resource_limits),
        })
    }

    fn active_process_count(&self) -> Result<u32, WindowsAdapterError> {
        u32::try_from(
            job_process_ids(self.job.handle)
                .map_err(|error| windows_adapter_from_io(&error))?
                .len(),
        )
        .map_err(|_| WindowsAdapterError::Failed)
    }

    fn history(&self) -> Result<JobProcessHistory, WindowsAdapterError> {
        self.observer.snapshot(self.job.handle)
    }

    fn wait_for_empty_history(
        &self,
        timeout: std::time::Duration,
    ) -> Result<JobProcessHistory, WindowsAdapterError> {
        self.observer
            .wait_for_empty_history(self.job.handle, timeout)
    }

    fn root_exit_code(&self) -> Result<Option<i32>, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0_u32;
                if unsafe { GetExitCodeProcess(self.process.0, &raw mut code) } == 0 {
                    return Err(last_windows_adapter_error());
                }
                Ok(Some(i32::from_ne_bytes(code.to_ne_bytes())))
            }
            _ => Err(last_windows_adapter_error()),
        }
    }

    fn terminate_and_reap(
        &mut self,
        requested_exit_code: u32,
    ) -> Result<(i32, JobProcessHistory), WindowsAdapterError> {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        self.job.terminate(requested_exit_code)?;
        wait_for_job_empty(self.job.handle, std::time::Duration::from_secs(5))?;
        if unsafe { WaitForSingleObject(self.process.0, 5_000) } != WAIT_OBJECT_0 {
            return Err(WindowsAdapterError::Timeout);
        }
        let exit_code = self.root_exit_code()?.ok_or(WindowsAdapterError::Failed)?;
        let history = self
            .observer
            .wait_for_empty_history(self.job.handle, std::time::Duration::from_secs(5))?;
        self.terminal = true;
        Ok((exit_code, history))
    }

    fn best_effort_cleanup(&mut self) -> bool {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
        if self.terminal {
            return true;
        }
        let _ = unsafe { TerminateProcess(self.process.0, 0xE1_04) };
        let _ = self.job.terminate(0xE1_04);
        let job_empty =
            wait_for_job_empty(self.job.handle, std::time::Duration::from_secs(5)).is_ok();
        let process_reaped = unsafe { WaitForSingleObject(self.process.0, 5_000) } == WAIT_OBJECT_0;
        self.terminal = job_empty && process_reaped;
        self.terminal
    }

    fn cleanup_after_pre_resume_failure(
        mut self,
        original: WindowsAdapterError,
    ) -> WindowsAdapterError {
        if self.best_effort_cleanup() {
            original
        } else {
            WindowsAdapterError::Timeout
        }
    }
}

#[cfg(windows)]
impl Drop for JobChildHandles {
    fn drop(&mut self) {
        let _ = self.best_effort_cleanup();
    }
}

#[cfg(windows)]
struct ExistingJobMemberHandles {
    process: OwnedProcessHandle,
    thread: OwnedProcessHandle,
    spawn_identity: ProcessIdentity,
    executable: PinnedExecutable,
    spec: SuspendedLaunchSpec,
    command_line_utf16: Vec<u16>,
    stdout: Option<std::fs::File>,
    stderr: Option<std::fs::File>,
    job_identity: JobObjectIdentity,
    terminal: bool,
}

#[cfg(windows)]
impl ExistingJobMemberHandles {
    fn fresh_evidence(
        &self,
        job: &RecoverableJobObject,
    ) -> Result<SuspendedProcessEvidence, WindowsAdapterError> {
        use windows_sys::Win32::System::Threading::GetProcessId;
        let process_id = unsafe { GetProcessId(self.process.0) };
        if process_id == 0 || process_id != self.spawn_identity.process_id {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let process = inspect_process_handle(process_id, self.process.0)
            .map_err(|error| windows_adapter_from_io(&error))?;
        if process.start_time_100ns != self.spawn_identity.start_time_100ns
            || !same_windows_path(&process.image_path, &self.spawn_identity.image_path)
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let observed_file = file_identity(Path::new(&process.image_path))
            .map_err(|error| windows_adapter_from_io(&error))?;
        if observed_file != self.executable.identity
            || !same_windows_path(&process.image_path, &self.spec.executable.to_string_lossy())
            || !job.contains_process(process_id)?
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let count = u32::try_from(
            job_process_ids(job.handle.0)
                .map_err(|error| windows_adapter_from_io(&error))?
                .len(),
        )
        .map_err(|_| WindowsAdapterError::Failed)?;
        if count == 0 {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(SuspendedProcessEvidence {
            process,
            executable: observed_file,
            job: self.job_identity.clone(),
            requested_executable: self.spec.executable.clone(),
            arguments: self.spec.arguments.clone(),
            working_directory: self.spec.working_directory.clone(),
            environment: self.spec.environment.clone(),
            command_line_utf16: self.command_line_utf16.clone(),
            job_process_count: count,
            // The member was assigned to a reopened pre-existing Job: the
            // ceilings enforced by that Job are unknown to this launch and
            // stay explicit here instead of a containment claim.
            enforced_limits: None,
        })
    }

    fn process_observation(&self) -> Result<Option<i32>, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0_u32;
                if unsafe { GetExitCodeProcess(self.process.0, &raw mut code) } == 0 {
                    return Err(last_windows_adapter_error());
                }
                Ok(Some(i32::from_ne_bytes(code.to_ne_bytes())))
            }
            _ => Err(last_windows_adapter_error()),
        }
    }

    fn terminate_and_reap(
        &mut self,
        requested_exit_code: u32,
        job: &RecoverableJobObject,
    ) -> Result<TerminatedExistingJobChild, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
        if unsafe { TerminateProcess(self.process.0, requested_exit_code) } == 0 {
            let error = last_windows_adapter_error();
            if self.process_observation()?.is_none() {
                return Err(error);
            }
        }
        if unsafe { WaitForSingleObject(self.process.0, 5_000) } != WAIT_OBJECT_0 {
            return Err(WindowsAdapterError::Timeout);
        }
        let observed_exit_code = self
            .process_observation()?
            .ok_or(WindowsAdapterError::Failed)?;
        let job_member_count = job.active_process_count()?;
        self.terminal = true;
        Ok(TerminatedExistingJobChild {
            process: self.spawn_identity.clone(),
            job: self.job_identity.clone(),
            requested_exit_code,
            observed_exit_code,
            job_member_count,
        })
    }

    fn best_effort_cleanup(&mut self) {
        use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
        if self.terminal {
            return;
        }
        let _ = unsafe { TerminateProcess(self.process.0, 0xE1_04) };
        let _ = unsafe { WaitForSingleObject(self.process.0, 5_000) };
        self.terminal = true;
    }
}

#[cfg(windows)]
impl Drop for ExistingJobMemberHandles {
    fn drop(&mut self) {
        self.best_effort_cleanup();
    }
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "existing-Job launch keeps assignment and fail-closed cleanup contiguous"
)]
fn spawn_existing_job_member(
    job: &RecoverableJobObject,
    spec: SuspendedLaunchSpec,
) -> Result<SuspendedExistingJobChild<'_>, WindowsAdapterError> {
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
        EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    };
    let executable = PinnedExecutable::open(&spec.executable)?;
    let application = nul_terminated_wide(spec.executable.as_os_str())
        .map_err(|error| windows_adapter_from_io(&error))?;
    let command_line_utf16 = command_line(&spec.executable, &spec.arguments)
        .map_err(|error| windows_adapter_from_io(&error))?;
    let mut command_line = command_line_utf16.clone();
    let mut environment = command_environment(&spec.environment);
    let current_directory = nul_terminated_wide(spec.working_directory.as_os_str())
        .map_err(|error| windows_adapter_from_io(&error))?;
    let (stdin_read, stdin_write) = inheritable_pipe_with_buffer(stdin_pipe_buffer_bytes(&spec))?;
    let (stdout_read, stdout_write) = inheritable_pipe()?;
    let (stderr_read, stderr_write) = inheritable_pipe()?;
    make_non_inheritable(stdin_write.0)?;
    make_non_inheritable(stdout_read.0)?;
    make_non_inheritable(stderr_read.0)?;
    let inherited_handles = [stdin_read.0, stdout_write.0, stderr_write.0];
    let attributes = ProcThreadAttributeList::for_inherited_handles(&inherited_handles)?;
    let mut startup = STARTUPINFOEXW {
        StartupInfo: windows_sys::Win32::System::Threading::STARTUPINFOW {
            cb: u32::try_from(std::mem::size_of::<STARTUPINFOEXW>())
                .map_err(|_| WindowsAdapterError::Failed)?,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: stdin_read.0,
            hStdOutput: stdout_write.0,
            hStdError: stderr_write.0,
            ..Default::default()
        },
        lpAttributeList: attributes.list,
    };
    let mut information = PROCESS_INFORMATION::default();
    // SAFETY: all buffers and the STARTUPINFOEX attribute list remain live;
    // handle inheritance is restricted to the explicit standard handles.
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | CREATE_NO_WINDOW
                | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_mut_ptr().cast(),
            current_directory.as_ptr(),
            &raw mut startup.StartupInfo,
            &raw mut information,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }
    if information.hProcess.is_null() || information.hThread.is_null() {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
        };
        let cleanup_process = if information.hProcess.is_null() && information.dwProcessId != 0 {
            unsafe { OpenProcess(PROCESS_TERMINATE | 0x0010_0000, 0, information.dwProcessId) }
        } else {
            information.hProcess
        };
        if !cleanup_process.is_null() {
            let _ = unsafe { TerminateProcess(cleanup_process, 0xE1_04) };
            let _ = unsafe { WaitForSingleObject(cleanup_process, 5_000) };
            if cleanup_process != information.hProcess {
                unsafe { CloseHandle(cleanup_process) };
            }
        }
        if !information.hThread.is_null() {
            unsafe { CloseHandle(information.hThread) };
        }
        if !information.hProcess.is_null() {
            unsafe { CloseHandle(information.hProcess) };
        }
        return Err(WindowsAdapterError::Failed);
    }
    // Parent keeps only the read sides. The one-shot request line, when the
    // admitted launch carried one, is written before the sole parent stdin
    // writer is closed, so the child reads that exact line and then observes
    // deterministic EOF instead of inherited input.
    let stdin_delivery = deliver_stdin_payload(&stdin_write, spec.stdin_payload.as_deref());
    drop(stdin_read);
    drop(stdin_write);
    drop(stdout_write);
    drop(stderr_write);
    let process = OwnedProcessHandle::new(information.hProcess)?;
    let thread = OwnedProcessHandle::new(information.hThread)?;
    let mut cleanup = SuspendedProcessCleanup {
        process: process.0,
        armed: true,
    };
    stdin_delivery?;
    let spawn_identity = inspect_process_handle(information.dwProcessId, process.0)
        .map_err(|error| windows_adapter_from_io(&error))?;
    let mut inner = ExistingJobMemberHandles {
        process,
        thread,
        spawn_identity,
        executable,
        spec,
        command_line_utf16,
        stdout: Some(stdout_read.into_file()),
        stderr: Some(stderr_read.into_file()),
        job_identity: job.identity().clone(),
        terminal: false,
    };
    job.assign_process_handle(inner.process.0)?;
    if !job.contains_process(inner.spawn_identity.process_id)? {
        inner.best_effort_cleanup();
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let observed_file = file_identity(Path::new(&inner.spawn_identity.image_path))
        .map_err(|error| windows_adapter_from_io(&error))?;
    if observed_file != inner.executable.identity
        || !same_windows_path(
            &inner.spawn_identity.image_path,
            &inner.spec.executable.to_string_lossy(),
        )
    {
        inner.best_effort_cleanup();
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    cleanup.disarm();
    Ok(SuspendedExistingJobChild { job, inner })
}

#[cfg(windows)]
impl<'job> SuspendedExistingJobChild<'job> {
    /// Returns the process identifier captured from the newly-created handle.
    /// The PID is only a diagnostic lookup key; all validation remains
    /// handle-bound and includes start time and image identity.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.inner.spawn_identity.process_id
    }

    /// Consumes the suspended member and requires caller-owned policy to
    /// return an opaque validation token before resume.
    ///
    /// # Errors
    /// Returns [`SuspendedValidationError::Mechanics`] when exact process or
    /// Job membership cannot be re-observed, or `Rejected` for the caller's
    /// policy error. Both paths kill and reap only this candidate.
    pub fn validate<V, E, F>(
        mut self,
        validator: F,
    ) -> Result<ValidatedSuspendedExistingJobChild<'job, V>, SuspendedValidationError<E>>
    where
        F: FnOnce(&SuspendedProcessEvidence) -> Result<V, E>,
    {
        let evidence = match self.inner.fresh_evidence(self.job) {
            Ok(evidence) => evidence,
            Err(error) => {
                self.inner.best_effort_cleanup();
                return Err(SuspendedValidationError::Mechanics(error));
            }
        };
        let validation = match validator(&evidence) {
            Ok(validation) => validation,
            Err(error) => {
                self.inner.best_effort_cleanup();
                return Err(SuspendedValidationError::Rejected(error));
            }
        };
        Ok(ValidatedSuspendedExistingJobChild {
            job: self.job,
            inner: self.inner,
            evidence,
            validation,
        })
    }

    /// Consumes and terminates only this suspended member.
    ///
    /// # Errors
    /// Returns a typed adapter error when the member cannot be terminated or
    /// reaped within the bounded wait.
    pub fn terminate(
        mut self,
        exit_code: u32,
    ) -> Result<TerminatedExistingJobChild, WindowsAdapterError> {
        self.inner.terminate_and_reap(exit_code, self.job)
    }
}

#[cfg(windows)]
impl<'job, V> ValidatedSuspendedExistingJobChild<'job, V> {
    #[must_use]
    pub fn evidence(&self) -> &SuspendedProcessEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn validation(&self) -> &V {
        &self.validation
    }

    /// Consumes the validated member and resumes exactly once.
    ///
    /// Fresh exact identity and Job membership are checked immediately before
    /// and after `ResumeThread`. Any unknown or inconsistent result kills and
    /// reaps only this member; the shared Job and its root remain untouched.
    ///
    /// # Errors
    /// Returns a typed adapter error when validation evidence changes,
    /// `ResumeThread` is unknown, or post-resume identity/membership is not
    /// exact. The candidate is killed and reaped on every error path.
    pub fn resume(mut self) -> Result<RunningExistingJobChild<'job, V>, WindowsAdapterError> {
        use windows_sys::Win32::System::Threading::ResumeThread;
        let before = match self.inner.fresh_evidence(self.job) {
            Ok(evidence) => evidence,
            Err(error) => {
                self.inner.best_effort_cleanup();
                return Err(error);
            }
        };
        if before.process != self.evidence.process
            || before.executable != self.evidence.executable
            || before.job != self.evidence.job
        {
            self.inner.best_effort_cleanup();
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let resumed = unsafe { ResumeThread(self.inner.thread.0) };
        if resumed == u32::MAX || resumed != 1 {
            let error = if resumed == u32::MAX {
                last_windows_adapter_error()
            } else {
                WindowsAdapterError::IdentityMismatch
            };
            self.inner.best_effort_cleanup();
            return Err(error);
        }
        let after = match self.inner.fresh_evidence(self.job) {
            Ok(evidence) => evidence,
            Err(error) => {
                self.inner.best_effort_cleanup();
                return Err(error);
            }
        };
        if after.process != before.process
            || after.executable != before.executable
            || after.job != before.job
        {
            self.inner.best_effort_cleanup();
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(RunningExistingJobChild {
            job: self.job,
            inner: self.inner,
            evidence: after,
            validation: self.validation,
        })
    }

    /// Consumes and terminates only this suspended member.
    ///
    /// # Errors
    /// Returns a typed adapter error when the member cannot be terminated or
    /// reaped within the bounded wait.
    pub fn terminate(
        mut self,
        exit_code: u32,
    ) -> Result<TerminatedExistingJobChild, WindowsAdapterError> {
        self.inner.terminate_and_reap(exit_code, self.job)
    }
}

#[cfg(windows)]
impl<V> RunningExistingJobChild<'_, V> {
    #[must_use]
    pub fn evidence(&self) -> &SuspendedProcessEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn validation(&self) -> &V {
        &self.validation
    }

    /// Returns the shared Job identity without exposing a Job handle.
    #[must_use]
    pub const fn job_identity(&self) -> &JobObjectIdentity {
        self.job.identity()
    }

    #[must_use]
    pub fn process(&self) -> &ProcessIdentity {
        self.evidence.process()
    }

    #[must_use]
    pub const fn executable_file_identity(&self) -> FileIdentity {
        self.evidence.executable_file_identity()
    }

    #[must_use]
    pub fn take_stdout(&mut self) -> Option<std::fs::File> {
        self.inner.stdout.take()
    }

    #[must_use]
    pub fn take_stderr(&mut self) -> Option<std::fs::File> {
        self.inner.stderr.take()
    }

    /// Observes only this process and the current member count of the shared
    /// Job. It never terminates the Job.
    ///
    /// # Errors
    /// Returns a typed adapter error when process exit state or Job membership
    /// cannot be observed.
    pub fn observe(&self) -> Result<ExistingJobMemberObservation, WindowsAdapterError> {
        let active_processes = self.job.active_process_count()?;
        match self.inner.process_observation()? {
            None => Ok(ExistingJobMemberObservation::Running { active_processes }),
            Some(exit_code) => Ok(ExistingJobMemberObservation::Exited {
                exit_code,
                active_processes,
            }),
        }
    }

    /// Terminates and reaps only this member process. The shared Job and all
    /// other members remain alive.
    ///
    /// # Errors
    /// Returns a typed adapter error when the member cannot be terminated or
    /// reaped within the bounded wait.
    pub fn terminate(
        mut self,
        exit_code: u32,
    ) -> Result<TerminatedExistingJobChild, WindowsAdapterError> {
        self.inner.terminate_and_reap(exit_code, self.job)
    }
}

/// Newly created suspended child. Validation and resume are consuming
/// typestate transitions, so neither transition can be repeated.
#[cfg(windows)]
pub struct SuspendedJobChild {
    inner: JobChildHandles,
}

/// Suspended child carrying the opaque token returned by caller-owned policy.
#[cfg(windows)]
pub struct ValidatedSuspendedJobChild<V> {
    inner: JobChildHandles,
    evidence: SuspendedProcessEvidence,
    validation: V,
}

/// Resumed child contained by the same kill-on-close Job Object.
#[cfg(windows)]
pub struct RunningJobChild<V> {
    inner: JobChildHandles,
    evidence: SuspendedProcessEvidence,
    validation: V,
}

/// Newly created suspended member of an already authenticated/reopened Job.
///
/// The lifetime ties the candidate to the retained recovery capability. The
/// candidate owns only its process resources; the shared Job remains owned by
/// [`RecoverableJobObject`].
#[cfg(windows)]
pub struct SuspendedExistingJobChild<'job> {
    job: &'job RecoverableJobObject,
    inner: ExistingJobMemberHandles,
}

/// Suspended existing-Job member carrying the caller-owned validation token.
#[cfg(windows)]
pub struct ValidatedSuspendedExistingJobChild<'job, V> {
    job: &'job RecoverableJobObject,
    inner: ExistingJobMemberHandles,
    evidence: SuspendedProcessEvidence,
    validation: V,
}

/// Running process member contained by an existing Job without owning it.
#[cfg(windows)]
pub struct RunningExistingJobChild<'job, V> {
    job: &'job RecoverableJobObject,
    inner: ExistingJobMemberHandles,
    evidence: SuspendedProcessEvidence,
    validation: V,
}

/// Idempotent observation of one running member in an existing Job.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExistingJobMemberObservation {
    Running {
        active_processes: u32,
    },
    Exited {
        exit_code: i32,
        active_processes: u32,
    },
}

/// Terminal receipt for one member process. The shared Job is never
/// terminated as part of producing this receipt.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminatedExistingJobChild {
    process: ProcessIdentity,
    job: JobObjectIdentity,
    requested_exit_code: u32,
    observed_exit_code: i32,
    job_member_count: u32,
}

#[cfg(windows)]
impl TerminatedExistingJobChild {
    /// Returns the exact process identity captured before launch.
    #[must_use]
    pub const fn process(&self) -> &ProcessIdentity {
        &self.process
    }

    /// Returns the shared Job identity without exposing a Job handle.
    #[must_use]
    pub const fn job_identity(&self) -> &JobObjectIdentity {
        &self.job
    }

    #[must_use]
    pub const fn requested_exit_code(&self) -> u32 {
        self.requested_exit_code
    }

    #[must_use]
    pub const fn observed_exit_code(&self) -> i32 {
        self.observed_exit_code
    }

    /// Returns the number of remaining Job members after this process was
    /// reaped. A non-zero value is expected when the Kernel root remains live.
    #[must_use]
    pub const fn remaining_job_members(&self) -> u32 {
        self.job_member_count
    }
}

/// Typed, idempotent observation of a resumed child.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunningJobObservation {
    Running {
        active_processes: u32,
    },
    RootExited {
        exit_code: i32,
        active_processes: u32,
    },
    Exited {
        exit_code: i32,
    },
}

/// Terminal receipt produced by one consuming termination transition.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminatedJobChild {
    process: ProcessIdentity,
    job: JobObjectIdentity,
    history: JobProcessHistory,
    requested_exit_code: u32,
    observed_exit_code: i32,
    job_empty: bool,
    root_reaped: bool,
}

#[cfg(windows)]
impl TerminatedJobChild {
    #[must_use]
    pub fn process(&self) -> &ProcessIdentity {
        &self.process
    }

    /// Returns the exact Job Object identity consumed by termination.
    #[must_use]
    pub const fn job_identity(&self) -> &JobObjectIdentity {
        &self.job
    }

    /// Returns the final historical process-membership observation.
    #[must_use]
    pub const fn history(&self) -> &JobProcessHistory {
        &self.history
    }

    #[must_use]
    pub const fn requested_exit_code(&self) -> u32 {
        self.requested_exit_code
    }

    #[must_use]
    pub const fn observed_exit_code(&self) -> i32 {
        self.observed_exit_code
    }

    #[must_use]
    pub const fn job_empty(&self) -> bool {
        self.job_empty
    }

    #[must_use]
    pub const fn root_reaped(&self) -> bool {
        self.root_reaped
    }
}

#[cfg(windows)]
impl SuspendedJobChild {
    /// Creates a child suspended in a fresh kill-on-close Job Object.
    ///
    /// # Errors
    /// Returns a typed adapter error for invalid deterministic material or any
    /// executable pin, process creation, identity, or Job assignment failure.
    pub fn spawn(spec: SuspendedLaunchSpec) -> Result<Self, WindowsAdapterError> {
        let sequence = JOB_OBJECT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let identity = JobObjectIdentity::new(format!(
            "Local\\Eliot-P02-{}-{sequence}",
            std::process::id()
        ))?;
        Self::spawn_named(spec, identity)
    }

    /// Creates a child suspended in one exact fresh named Job Object.
    ///
    /// The Job completion port is attached before assignment, and only the
    /// child-side standard handles are inheritable. Validation and resume stay
    /// separate consuming transitions.
    ///
    /// The Job carries no resource ceilings: this form is reserved for core
    /// branches whose approved posture is kill-on-close containment without a
    /// job-memory ceiling. Worker launch descriptors with a required memory
    /// ceiling must use [`Self::spawn_named_with_limits`] with
    /// [`JobObjectLimits::require_memory_ceiling`] and never fall back here.
    ///
    /// # Errors
    /// Returns a typed adapter error for a Job-name collision or any pipe,
    /// process, identity, or assignment failure.
    pub fn spawn_named(
        spec: SuspendedLaunchSpec,
        job_identity: JobObjectIdentity,
    ) -> Result<Self, WindowsAdapterError> {
        Self::spawn_named_with_limits(spec, job_identity, JobObjectLimits::default())
    }

    /// Creates a child suspended in a fresh named Job with resource ceilings.
    ///
    /// This entry point does not claim a Host-owned outer kill domain. Launchers
    /// that start a Host-owned outer branch or a per-generation nested Job
    /// Object use [`SuspendedJobChild::spawn_named_host_outer_kill_domain`] and
    /// [`SuspendedJobChild::spawn_nested_in_kernel_outer_kill_domain`] instead,
    /// so a Kernel or Host launch cannot reach execution with an unverified
    /// containment.
    ///
    /// # Errors
    /// Returns a typed adapter error before resume when any limit, Job, pipe,
    /// process, identity, or assignment operation fails.
    pub fn spawn_named_with_limits(
        spec: SuspendedLaunchSpec,
        job_identity: JobObjectIdentity,
        resource_limits: JobObjectLimits,
    ) -> Result<Self, WindowsAdapterError> {
        Self::spawn_named_job_child(spec, job_identity, resource_limits, None, None)
    }

    /// Creates a child suspended in one exact fresh Host-owned outer Job
    /// Object.
    ///
    /// `job_identity` must be a Host-owned outer kill domain Job Object name;
    /// a per-generation/per-attempt nested name is refused, because `I1.6` puts
    /// kill-on-close at the outer ownership boundary. The kill domain owner
    /// identity carried on the created Job Object record is resolved from that
    /// one name, so the record can never disagree with the name a launcher
    /// presented and neither the Kernel nor the Watchdog launcher can present
    /// the other's outer Job Object. `resource_limits` stays the caller's
    /// already-admitted value; this entry point never adds a default, cap, or
    /// fallback ceiling.
    ///
    /// The child is created only after this build's containment probe for the
    /// resolved kill domain has observed assignment, permitted nesting, and
    /// outer kill-on-close, so a build that cannot establish the containment
    /// fails visibly instead of degrading silently.
    ///
    /// # Errors
    /// Returns `IdentityMismatch` when the name is not a Host-owned outer kill
    /// domain name, `Unavailable` when this build cannot establish the required
    /// containment, and otherwise a typed adapter error before resume.
    pub fn spawn_named_host_outer_kill_domain(
        spec: SuspendedLaunchSpec,
        job_identity: JobObjectIdentity,
        resource_limits: JobObjectLimits,
    ) -> Result<Self, WindowsAdapterError> {
        let outer_kill_domain = outer_kill_domain_of_job_name(job_identity.name())
            .ok_or(WindowsAdapterError::IdentityMismatch)?;
        require_probed_outer_kill_domain(outer_kill_domain)?;
        Self::spawn_named_job_child(
            spec,
            job_identity,
            resource_limits,
            Some(outer_kill_domain),
            None,
        )
    }

    /// Creates a child suspended in a fresh per-generation/per-attempt Job
    /// Object nested inside the Host-owned Kernel outer kill domain.
    ///
    /// `I1.6` keeps every Kernel descendant inside the Host-owned Kernel Job
    /// Object while it MAY additionally enter nested per-Module/per-attempt Job
    /// Objects, so the nested Job Object itself carries no outer kill domain:
    /// nesting must never mint a second one. `resource_limits` stays the
    /// caller's already-admitted value; this entry point never adds a default,
    /// cap, or fallback ceiling.
    ///
    /// The exact retained Host Kernel Job binding is reopened and its root is
    /// revalidated before launch. The current launcher and the still-suspended
    /// child must both be members of that exact outer Job, and the child must
    /// also be in its fresh per-attempt Job. This build's containment probe
    /// must observe that nesting is permitted and outer kill-on-close still
    /// governs before the child is created.
    ///
    /// That probe verdict is build-scoped platform capability and is not
    /// sufficient on its own: this launch additionally reads back the reopened
    /// outer Job's own kill-on-close flag and resource ceilings, so the cached
    /// probe success cannot attest a Job it never observed.
    ///
    /// # Errors
    /// Returns `Unavailable` when this build cannot establish the required
    /// containment, `IdentityMismatch` when the outer Job does not carry
    /// kill-on-close with the admitted ceilings, and otherwise a typed adapter
    /// error before resume.
    pub fn spawn_nested_in_kernel_outer_kill_domain(
        spec: SuspendedLaunchSpec,
        job_identity: JobObjectIdentity,
        resource_limits: JobObjectLimits,
        outer_binding: RecoverableJobBinding,
    ) -> Result<Self, WindowsAdapterError> {
        require_probed_outer_kill_domain(OuterKillDomain::Kernel)?;
        if !OuterKillDomain::Kernel.owns_host_job_name(outer_binding.job_identity().name()) {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let outer_job = RecoverableJobObject::open(outer_binding)?;
        let current_process = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
        let current_identity = inspect_process_handle(std::process::id(), current_process)
            .map_err(|error| windows_adapter_from_io(&error))?;
        if outer_job.binding().root().process() != &current_identity
            || !is_process_in_job(current_process, outer_job.handle.0)?
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        // The build-level probe verdict alone cannot permit this launch: the
        // exact outer Job this launch will use must itself be attested as
        // carrying kill-on-close. A cached probe success is unrelated evidence
        // about temporary probe Job Objects.
        require_attested_outer_job(OuterKillDomain::Kernel, &outer_job)?;
        Self::spawn_named_job_child(spec, job_identity, resource_limits, None, Some(&outer_job))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "suspended launch and fail-closed cleanup ordering remain contiguous"
    )]
    fn spawn_named_job_child(
        spec: SuspendedLaunchSpec,
        job_identity: JobObjectIdentity,
        resource_limits: JobObjectLimits,
        outer_kill_domain: Option<OuterKillDomain>,
        required_outer_job: Option<&RecoverableJobObject>,
    ) -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::System::Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
            EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
            STARTUPINFOEXW,
        };
        // The declared execution identity is resolved to a concrete primary
        // token before the child is created. `CreateProcessW` cannot take a
        // token, so this launch path always creates through
        // `CreateProcessAsUserW` with the token this mode selected. A mode
        // whose token cannot be obtained stops here: it never falls back to
        // the launching process's own token.
        let selected = resolve_execution_identity_token(spec.execution_identity())?;
        if selected.mode.is_user_mode() && selected.expected_session_id == 0 {
            // A `user_mode` launch cannot land in session 0, which is the
            // machine SCM session. Landing there would attach the child to an
            // SCM service session this launch never declared.
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let executable = PinnedExecutable::open(&spec.executable)?;
        let application = nul_terminated_wide(spec.executable.as_os_str())
            .map_err(|error| windows_adapter_from_io(&error))?;
        let command_line_utf16 = command_line(&spec.executable, &spec.arguments)
            .map_err(|error| windows_adapter_from_io(&error))?;
        let mut command_line = command_line_utf16.clone();
        let mut environment = command_environment(&spec.environment);
        let current_directory = nul_terminated_wide(spec.working_directory.as_os_str())
            .map_err(|error| windows_adapter_from_io(&error))?;
        let (stdin_read, stdin_write) =
            inheritable_pipe_with_buffer(stdin_pipe_buffer_bytes(&spec))?;
        let (stdout_read, stdout_write) = inheritable_pipe()?;
        let (stderr_read, stderr_write) = inheritable_pipe()?;
        make_non_inheritable(stdin_write.0)?;
        make_non_inheritable(stdout_read.0)?;
        make_non_inheritable(stderr_read.0)?;
        let inherited_handles = [stdin_read.0, stdout_write.0, stderr_write.0];
        let attributes = ProcThreadAttributeList::for_inherited_handles(&inherited_handles)?;
        let job = match outer_kill_domain {
            Some(domain) => {
                let created = JobObject::new_named_outer_kill_on_close_with_limits(
                    domain,
                    job_identity,
                    resource_limits,
                )?;
                // This launch created the outer Job itself, so the kill-on-close
                // flag and ceilings that were actually installed on it are read
                // back from it before any child exists.
                attest_created_outer_job(&created, domain, resource_limits)?;
                created
            }
            None => JobObject::new_named_kill_on_close_with_limits(job_identity, resource_limits)?,
        };
        let observer = JobProcessObserver::attach(job.handle)?;
        let mut startup = STARTUPINFOEXW {
            StartupInfo: windows_sys::Win32::System::Threading::STARTUPINFOW {
                cb: u32::try_from(std::mem::size_of::<STARTUPINFOEXW>())
                    .map_err(|_| WindowsAdapterError::Failed)?,
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: stdin_read.0,
                hStdOutput: stdout_write.0,
                hStdError: stderr_write.0,
                ..Default::default()
            },
            lpAttributeList: attributes.list,
        };
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: all buffers and the STARTUPINFOEX attribute list remain live;
        // handle inheritance is restricted to `inherited_handles`; and
        // `selected.token` is a live primary token retained across this call.
        // `CreateProcessAsUserW` is used instead of `CreateProcessW` because
        // `I1.6` requires the child to be created under a declared identity and
        // `CreateProcessW` has no token parameter, so it can only ever produce a
        // child running as the caller.
        if unsafe {
            windows_sys::Win32::System::Threading::CreateProcessAsUserW(
                selected.token.0,
                application.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                CREATE_SUSPENDED
                    | CREATE_UNICODE_ENVIRONMENT
                    | CREATE_NO_WINDOW
                    | EXTENDED_STARTUPINFO_PRESENT,
                environment.as_mut_ptr().cast(),
                current_directory.as_ptr(),
                &raw mut startup.StartupInfo,
                &raw mut information,
            )
        } == 0
        {
            return Err(last_windows_adapter_error());
        }
        if information.hProcess.is_null() || information.hThread.is_null() {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::{
                OpenProcess, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
            };
            let cleanup_process = if information.hProcess.is_null() && information.dwProcessId != 0
            {
                unsafe { OpenProcess(PROCESS_TERMINATE | 0x0010_0000, 0, information.dwProcessId) }
            } else {
                information.hProcess
            };
            let mut cleanup_observed = false;
            if !cleanup_process.is_null() {
                let _ = unsafe { TerminateProcess(cleanup_process, 0xE1_04) };
                cleanup_observed = unsafe { WaitForSingleObject(cleanup_process, 5_000) }
                    == windows_sys::Win32::Foundation::WAIT_OBJECT_0;
                if cleanup_process != information.hProcess {
                    unsafe { CloseHandle(cleanup_process) };
                }
            }
            if !information.hThread.is_null() {
                unsafe { CloseHandle(information.hThread) };
            }
            if !information.hProcess.is_null() {
                unsafe { CloseHandle(information.hProcess) };
            }
            return Err(if cleanup_observed {
                WindowsAdapterError::Failed
            } else {
                WindowsAdapterError::Timeout
            });
        }
        // A one-shot request is delivered before resume and followed by EOF.
        // Live mode keeps the sole parent writer attached to this exact child
        // lifecycle; it is transferred only after the child resumes. The
        // delivery outcome is surfaced only after the kill-on-reap guard below
        // is armed, so a failed one-shot write cannot leave an unresumed child.
        let stdin_delivery = if spec.retain_stdin_writer {
            if spec.stdin_payload.is_some() {
                Err(WindowsAdapterError::InvalidInput)
            } else {
                Ok(())
            }
        } else {
            deliver_stdin_payload(&stdin_write, spec.stdin_payload.as_deref())
        };
        drop(stdin_read);
        let stdin = if spec.retain_stdin_writer && stdin_delivery.is_ok() {
            Some(stdin_write.into_file())
        } else {
            drop(stdin_write);
            None
        };
        drop(stdout_write);
        drop(stderr_write);
        let mut cleanup = SuspendedProcessCleanup {
            process: information.hProcess,
            armed: true,
        };
        let process = match OwnedProcessHandle::new(information.hProcess) {
            Ok(process) => process,
            Err(error) => return Err(cleanup_error(&mut cleanup, error)),
        };
        let thread = match OwnedProcessHandle::new(information.hThread) {
            Ok(thread) => thread,
            Err(error) => return Err(cleanup_error(&mut cleanup, error)),
        };
        if let Err(error) = stdin_delivery {
            return Err(cleanup_error(&mut cleanup, error));
        }
        let spawn_identity =
            match inspect_process_handle(information.dwProcessId, information.hProcess) {
                Ok(identity) => identity,
                Err(error) => {
                    return Err(cleanup_error(&mut cleanup, windows_adapter_from_io(&error)));
                }
            };
        let inner = JobChildHandles {
            process,
            thread,
            job,
            resource_limits,
            spawn_identity,
            executable,
            spec,
            command_line_utf16,
            stdin,
            stdout: Some(stdout_read.into_file()),
            stderr: Some(stderr_read.into_file()),
            observer,
            terminal: false,
        };
        cleanup.disarm();
        let post_create = (|| {
            inner.job.assign_process_handle(inner.process.0)?;
            inner
                .observer
                .capture_pid(inner.spawn_identity.process_id)?;
            if !inner
                .job
                .contains_process(inner.spawn_identity.process_id)?
                || !is_process_in_job(inner.process.0, inner.job.handle)?
            {
                return Err(WindowsAdapterError::IdentityMismatch);
            }
            if let Some(outer_job) = required_outer_job {
                // Per-child attestation of the exact outer Job. This is not the
                // cached build-level probe verdict: it reads this outer Job's own
                // kill-on-close flag and ceilings, and requires this still
                // suspended child to be a member of this exact handle and of its
                // fresh per-attempt Job. Unrelated probe success cannot stand in
                // for any of it.
                require_attested_outer_job(OuterKillDomain::Kernel, outer_job)?;
                if !is_process_in_job(inner.process.0, outer_job.handle.0)? {
                    return Err(WindowsAdapterError::IdentityMismatch);
                }
            }
            let observed_file = file_identity(Path::new(&inner.spawn_identity.image_path))
                .map_err(|error| windows_adapter_from_io(&error))?;
            if observed_file != inner.executable.identity
                || !same_windows_path(
                    &inner.spawn_identity.image_path,
                    &inner.spec.executable.to_string_lossy(),
                )
            {
                return Err(WindowsAdapterError::IdentityMismatch);
            }
            // Read the launched child's own token back and compare it to the
            // identity this launch declared. Selecting a token and asserting
            // it is not the same as proving it: this is the observation that
            // turns `I1.6`'s "uses a dedicated low-privilege service identity"
            // and "runs under the current user" into a checked outcome. A child
            // running under any other identity fails closed here, before resume.
            let observed_token = crate::process_token_identity(inner.process.0)?;
            if observed_token.0 != selected.expected_sid
                || observed_token.1 != selected.expected_session_id
            {
                return Err(WindowsAdapterError::IdentityMismatch);
            }
            Ok(())
        })();
        if let Err(error) = post_create {
            return Err(inner.cleanup_after_pre_resume_failure(error));
        }
        Ok(Self { inner })
    }

    #[must_use]
    pub const fn id(&self) -> u32 {
        self.inner.spawn_identity.process_id
    }

    /// Consumes the unvalidated state and requires caller-owned policy to
    /// return an opaque validation token over fresh P-02 mechanics evidence.
    ///
    /// # Errors
    /// Returns `Mechanics` for failed retained-handle validation or `Rejected`
    /// with the caller's own policy/permit error when cleanup is observed.
    /// `UnknownOutcome` preserves the attempt when termination cannot be
    /// observed for the still-suspended process and its Job.
    pub fn validate<V, E, F>(
        mut self,
        validator: F,
    ) -> Result<ValidatedSuspendedJobChild<V>, SuspendedValidationError<E>>
    where
        F: FnOnce(&SuspendedProcessEvidence) -> Result<V, E>,
    {
        let evidence = match self.inner.fresh_evidence() {
            Ok(evidence) => evidence,
            Err(error) => {
                return Err(if self.inner.best_effort_cleanup() {
                    SuspendedValidationError::Mechanics(error)
                } else {
                    SuspendedValidationError::UnknownOutcome
                });
            }
        };
        let validation = match validator(&evidence) {
            Ok(validation) => validation,
            Err(error) => {
                return Err(if self.inner.best_effort_cleanup() {
                    SuspendedValidationError::Rejected(error)
                } else {
                    SuspendedValidationError::UnknownOutcome
                });
            }
        };
        Ok(ValidatedSuspendedJobChild {
            inner: self.inner,
            evidence,
            validation,
        })
    }

    /// Consumes and terminates an unvalidated child without resuming it.
    ///
    /// # Errors
    /// Returns a typed adapter error when termination or bounded reap fails.
    pub fn terminate(mut self, exit_code: u32) -> Result<TerminatedJobChild, WindowsAdapterError> {
        terminalize(&mut self.inner, exit_code)
    }
}

#[cfg(windows)]
impl<V> ValidatedSuspendedJobChild<V> {
    #[must_use]
    pub fn evidence(&self) -> &SuspendedProcessEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn validation(&self) -> &V {
        &self.validation
    }

    /// Consumes the validated suspended state and resumes exactly once.
    ///
    /// # Errors
    /// Returns a typed adapter error when Windows rejects `ResumeThread`; the
    /// error path kills and reaps the full Job.
    pub fn resume(mut self) -> Result<RunningJobChild<V>, WindowsAdapterError> {
        use windows_sys::Win32::System::Threading::ResumeThread;
        if unsafe { ResumeThread(self.inner.thread.0) } == u32::MAX {
            let error = last_windows_adapter_error();
            return Err(if self.inner.best_effort_cleanup() {
                error
            } else {
                WindowsAdapterError::Timeout
            });
        }
        Ok(RunningJobChild {
            inner: self.inner,
            evidence: self.evidence,
            validation: self.validation,
        })
    }

    /// Consumes and terminates a validated child without resuming it.
    ///
    /// # Errors
    /// Returns a typed adapter error when termination or bounded reap fails.
    pub fn terminate(mut self, exit_code: u32) -> Result<TerminatedJobChild, WindowsAdapterError> {
        terminalize(&mut self.inner, exit_code)
    }
}

#[cfg(windows)]
impl<V> RunningJobChild<V> {
    #[must_use]
    pub fn evidence(&self) -> &SuspendedProcessEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn validation(&self) -> &V {
        &self.validation
    }

    /// Returns the exact owner-scoped Job Object identity.
    #[must_use]
    pub const fn job_identity(&self) -> &JobObjectIdentity {
        self.inner.job.identity()
    }

    /// Transfers ownership of the process stdout read handle exactly once.
    #[must_use]
    pub fn take_stdout(&mut self) -> Option<std::fs::File> {
        self.inner.stdout.take()
    }

    /// Transfers ownership of the process stderr read handle exactly once.
    #[must_use]
    pub fn take_stderr(&mut self) -> Option<std::fs::File> {
        self.inner.stderr.take()
    }

    /// Transfers the live standard-input writer exactly once when this child
    /// was launched with [`SuspendedLaunchSpec::with_live_stdin`].
    #[must_use]
    pub fn take_stdin_writer(&mut self) -> Option<std::fs::File> {
        self.inner.stdin.take()
    }

    /// Returns an idempotent observation without changing typestate.
    ///
    /// # Errors
    /// Returns a typed adapter error when process or Job state cannot be read.
    pub fn observe(&self) -> Result<RunningJobObservation, WindowsAdapterError> {
        let active_processes = self.inner.active_process_count()?;
        match self.inner.root_exit_code()? {
            None => Ok(RunningJobObservation::Running { active_processes }),
            Some(exit_code) if active_processes == 0 => {
                Ok(RunningJobObservation::Exited { exit_code })
            }
            Some(exit_code) => Ok(RunningJobObservation::RootExited {
                exit_code,
                active_processes,
            }),
        }
    }

    /// Returns identities observed in the Job so far, including exited members.
    ///
    /// # Errors
    /// Returns a typed adapter error when membership or identity cannot be read.
    pub fn job_processes(&self) -> Result<Vec<ProcessIdentity>, WindowsAdapterError> {
        Ok(self
            .inner
            .history()?
            .processes()
            .iter()
            .map(|process| process.process().clone())
            .collect())
    }

    /// Returns the current number of live Job members.
    ///
    /// # Errors
    /// Returns a typed adapter error when Job state cannot be queried.
    pub fn active_process_count(&self) -> Result<u32, WindowsAdapterError> {
        self.inner.active_process_count()
    }

    /// Returns historical membership observed so far.
    ///
    /// While the Job is active, `complete` is necessarily false because more
    /// descendants may still be created.
    ///
    /// # Errors
    /// Returns a typed adapter error when current Job membership cannot be read.
    pub fn process_history(&self) -> Result<JobProcessHistory, WindowsAdapterError> {
        self.inner.history()
    }

    /// Waits for the Job to become empty and returns the final history.
    ///
    /// A timed-out or identity-gap result is returned with `complete == false`;
    /// callers must project that as UNKNOWN rather than tree closure.
    ///
    /// # Errors
    /// Returns a typed adapter error when Job membership cannot be observed.
    pub fn wait_for_empty_history(
        &self,
        timeout: std::time::Duration,
    ) -> Result<JobProcessHistory, WindowsAdapterError> {
        self.inner.wait_for_empty_history(timeout)
    }

    /// Terminates and reaps the complete Job without consuming this owner.
    ///
    /// A failed termination or bounded wait leaves the process and Job
    /// handles attached to this value so the owning executor can retry and
    /// retain exact cleanup evidence.
    ///
    /// # Errors
    ///
    /// Returns a typed adapter error when Job termination, bounded reap, or
    /// final process evidence capture fails.
    pub fn terminate_in_place(
        &mut self,
        exit_code: u32,
    ) -> Result<TerminatedJobChild, WindowsAdapterError> {
        terminalize(&mut self.inner, exit_code)
    }

    /// Consumes and terminates the complete Job exactly once.
    ///
    /// # Errors
    /// Returns a typed adapter error when termination or bounded reap fails.
    pub fn terminate(mut self, exit_code: u32) -> Result<TerminatedJobChild, WindowsAdapterError> {
        self.terminate_in_place(exit_code)
    }
}

/// Cancels one synchronous read issued by a capture reader thread.
///
/// `Ok(false)` means that the thread had no pending synchronous I/O when the
/// cancellation was requested; callers still need to use their bounded wait
/// policy before joining it.
///
/// # Errors
///
/// Returns a typed adapter error when Windows rejects the cancellation for a
/// reason other than there being no pending synchronous I/O.
#[cfg(windows)]
pub fn cancel_capture_thread_io(
    thread: &std::thread::JoinHandle<()>,
) -> Result<bool, WindowsAdapterError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;
    use windows_sys::Win32::System::IO::CancelSynchronousIo;

    if unsafe { CancelSynchronousIo(thread.as_raw_handle()) } != 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_NOT_FOUND.cast_signed()) {
        Ok(false)
    } else {
        Err(windows_adapter_from_io(&error))
    }
}

#[cfg(windows)]
fn terminalize(
    inner: &mut JobChildHandles,
    requested_exit_code: u32,
) -> Result<TerminatedJobChild, WindowsAdapterError> {
    let process = inner.spawn_identity.clone();
    let (observed_exit_code, history) = inner.terminate_and_reap(requested_exit_code)?;
    Ok(TerminatedJobChild {
        process,
        job: inner.job.identity().clone(),
        history,
        requested_exit_code,
        observed_exit_code,
        job_empty: true,
        root_reaped: true,
    })
}

#[cfg(all(test, windows))]
mod outer_job_attestation_tests {
    //! AUD6: the nesting/kill-on-close probe is platform capability for the
    //! supported build, and it is bound to the actual Job topology and the
    //! actual launch. These tests prove the per-launch attestation on THIS outer
    //! Job: a cached build-level verdict cannot stand in for a Job it never
    //! observed, and an unattestable launch is unavailable for itself alone.

    use super::{
        JOB_OBJECT_SEQUENCE, JobObject, JobObjectIdentity, JobObjectLimits, ObservedJobContainment,
        OuterKillDomain, attest_created_outer_job, observed_job_containment,
        probe_launch_containment,
    };
    use windows_sys::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    };

    /// One unique name per call, so two attestations in one process never
    /// collide on the object-manager name.
    fn unique_name(kind: &str, domain_prefix: bool) -> JobObjectIdentity {
        let sequence = JOB_OBJECT_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = if domain_prefix {
            format!(
                "Local\\Eliot-Host-Kernel-{kind}-{}-{sequence}",
                std::process::id()
            )
        } else {
            format!("Local\\Eliot-P04-{kind}-{}-{sequence}", std::process::id())
        };
        JobObjectIdentity::new(name).unwrap_or_else(|error| panic!("Job name failed: {error}"))
    }

    /// Reads one Job Object's current extended limit information, so a test can
    /// change one flag and then observe exactly what the kernel holds.
    fn read_limits(
        job: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<JOBOBJECT_EXTENDED_LIMIT_INFORMATION, super::WindowsAdapterError> {
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let length = u32::try_from(std::mem::size_of_val(&information))
            .map_err(|_| super::WindowsAdapterError::Failed)?;
        // SAFETY: `job` is live for the call and `information` is a writable,
        // correctly sized, zeroed buffer for the exact class queried.
        let queried = unsafe {
            QueryInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw mut information).cast(),
                length,
                std::ptr::null_mut(),
            )
        };
        if queried == 0 {
            return Err(super::WindowsAdapterError::Unavailable);
        }
        Ok(information)
    }

    /// Sets or clears `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` on one live Job
    /// Object, leaving every other limit exactly as it was, and returns what the
    /// kernel then reports through the production read-back.
    fn set_kill_on_close(
        job: windows_sys::Win32::Foundation::HANDLE,
        enabled: bool,
    ) -> Result<ObservedJobContainment, super::WindowsAdapterError> {
        let mut limits = read_limits(job)?;
        let length = u32::try_from(std::mem::size_of_val(&limits))
            .map_err(|_| super::WindowsAdapterError::Failed)?;
        if enabled {
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        } else {
            limits.BasicLimitInformation.LimitFlags &= !JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        }
        // SAFETY: the same live handle and exactly sized buffer, re-stating this
        // Job Object's own limits.
        let applied = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                length,
            )
        };
        if applied == 0 {
            return Err(super::WindowsAdapterError::Unavailable);
        }
        observed_job_containment(job)
    }

    /// AUD6 (b): the reopened outer Job's kill-on-close flag is read back, so a
    /// cached build-level probe success cannot attest a Job that does not carry
    /// the flag. Windows accepts the flag change; the attestation is what
    /// refuses the launch, and it refuses exactly one launch.
    #[test]
    fn outer_job_kill_on_close_is_read_back_and_a_job_without_it_is_refused() {
        let outer = JobObject::new_named_outer_kill_on_close_with_limits(
            OuterKillDomain::Kernel,
            unique_name("audit6-koc", true),
            JobObjectLimits::default(),
        )
        .unwrap_or_else(|error| panic!("outer Job creation failed: {error}"));
        // Platform capability: this build's verdict is about temporary probe
        // Job Objects and is cached process-wide.
        let cached = probe_launch_containment(OuterKillDomain::Kernel)
            .unwrap_or_else(|error| panic!("build containment probe failed: {error}"));
        assert_eq!(cached.domain(), OuterKillDomain::Kernel);
        assert_ne!(cached.distinct_domain(), OuterKillDomain::Kernel);
        let admitted = JobObjectLimits::default();
        // This outer Job is attested while it still carries the flag.
        attest_created_outer_job(&outer, OuterKillDomain::Kernel, admitted)
            .unwrap_or_else(|error| panic!("kill-on-close outer Job was not attested: {error}"));

        // Strip the flag from THIS Job Object. The cached verdict above is
        // unchanged and still successful, and is unrelated to this Job.
        let cleared = set_kill_on_close(outer.handle, false)
            .unwrap_or_else(|error| panic!("clearing kill-on-close failed: {error}"));
        assert!(!cleared.kill_on_close());
        assert!(
            probe_launch_containment(OuterKillDomain::Kernel).is_ok(),
            "the cached build-level verdict must be unaffected by this Job's flag",
        );
        assert_eq!(
            attest_created_outer_job(&outer, OuterKillDomain::Kernel, admitted).err(),
            Some(super::WindowsAdapterError::IdentityMismatch),
        );

        // Restoring the flag on the same Job attests it again: the refusal above
        // was this Job's own evidence, never the build-level verdict.
        let restored = set_kill_on_close(outer.handle, true)
            .unwrap_or_else(|error| panic!("restoring kill-on-close failed: {error}"));
        assert!(restored.kill_on_close());
        attest_created_outer_job(&outer, OuterKillDomain::Kernel, admitted)
            .unwrap_or_else(|error| panic!("restored outer Job was not attested: {error}"));
    }

    /// AUD6 (a) and (b): the limits actually installed on the outer Job are read
    /// back and compared against the admitted values, so an outer Job whose
    /// ceilings or kill-on-close flag differ from what this launch admitted is
    /// refused, and the absent ceiling stays an absent ceiling.
    #[test]
    fn outer_job_limits_are_read_back_and_a_different_ceiling_is_refused() {
        let admitted = JobObjectLimits::new(None, Some(67_108_864), Some(4), Some(40))
            .unwrap_or_else(|error| panic!("admitted limits failed: {error}"));
        let outer = JobObject::new_named_outer_kill_on_close_with_limits(
            OuterKillDomain::Kernel,
            unique_name("audit6-limits", true),
            admitted,
        )
        .unwrap_or_else(|error| panic!("outer Job creation failed: {error}"));
        let observed = observed_job_containment(outer.handle)
            .unwrap_or_else(|error| panic!("outer Job read-back failed: {error}"));
        assert!(observed.kill_on_close());
        assert_eq!(observed.limits, admitted);
        attest_created_outer_job(&outer, OuterKillDomain::Kernel, admitted)
            .unwrap_or_else(|error| panic!("installed outer Job was not attested: {error}"));
        // A different admitted value names a different containment, so the same
        // Job is not attested for it.
        assert_eq!(
            attest_created_outer_job(
                &outer,
                OuterKillDomain::Kernel,
                JobObjectLimits::new(None, Some(67_108_865), Some(4), Some(40))
                    .unwrap_or_else(|error| panic!("limits failed: {error}")),
            )
            .err(),
            Some(super::WindowsAdapterError::IdentityMismatch),
        );
        // An absent ceiling is read back as absent, never as a zero reading.
        let without_memory = JobObject::new_named_outer_kill_on_close_with_limits(
            OuterKillDomain::Kernel,
            unique_name("audit6-no-memory", true),
            JobObjectLimits::default(),
        )
        .unwrap_or_else(|error| panic!("outer Job creation failed: {error}"));
        assert_eq!(
            observed_job_containment(without_memory.handle)
                .unwrap_or_else(|error| panic!("read-back failed: {error}"))
                .limits,
            JobObjectLimits::default(),
        );
        // A nested per-attempt Job name is never a Host-owned outer kill domain,
        // so it can never be attested as one.
        let nested = JobObject::new_named_kill_on_close_with_limits(
            unique_name("audit6-nested", false),
            admitted,
        )
        .unwrap_or_else(|error| panic!("nested Job creation failed: {error}"));
        assert_eq!(nested.outer_kill_domain(), None);
        assert_eq!(
            attest_created_outer_job(&nested, OuterKillDomain::Kernel, admitted).err(),
            Some(super::WindowsAdapterError::IdentityMismatch),
        );
    }
}

#[cfg(all(test, windows))]
mod a1_a3_aud3_launch_domain_tests {
    //! Issue #1888 A1 / A3 / AUD3 against the real Job Objects of one launch.
    //!
    //! Every assertion in this module reads a live kernel object. It opens the
    //! exact named Job Object with `OpenJobObjectW` and asks the kernel
    //! `QueryInformationJobObject(JobObjectBasicProcessIdList)` for the CURRENT
    //! member PIDs, and asks `IsProcessInJob` about an actual process handle. No
    //! assertion reads a Job name, a serialized binding, or any value the launcher
    //! produced, so a probe that established something only about temporary
    //! sequence-named Job Objects cannot satisfy any of them.
    //!
    //! One structural constraint shapes the fixtures. Windows nesting follows the
    //! parent's real Job chain, so a child can only be nested inside a
    //! Host-owned Kernel outer Job Object when its launcher is already a member
    //! of that Job. Every launch API in this crate assigns the child to a Job, so
    //! the launcher cannot be created by this crate either: it is created with
    //! `std::process::Command`, which leaves it outside any Job, and it then
    //! places ITSELF inside the Host Kernel outer Job before launching the Module
    //! child through the nested launch API. The test process never enters that
    //! Job, which is what lets it close the outer Job Object and observe the
    //! kill-on-close consequence without killing the test harness.

    use super::{
        JOB_OBJECT_SEQUENCE, JobObject, JobObjectIdentity, JobObjectLimits, OuterKillDomain,
        ProcessObservation, RecoverableJobBinding, SuspendedJobChild, SuspendedLaunchSpec,
        WindowsAdapterError, job_process_ids,
    };
    use crate::{file_identity, inspect_process_identity};
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, IsProcessInJob, OpenJobObjectW,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SET_QUOTA, PROCESS_TERMINATE, WaitForSingleObject,
    };

    /// `JOB_OBJECT_QUERY_ACCESS`: enough to ask the kernel for a Job's members.
    const JOB_OBJECT_QUERY_ACCESS: u32 = 0x0004;
    /// `JOB_OBJECT_ASSIGN_PROCESS`: enough to place a process into a Job.
    const JOB_OBJECT_ASSIGN_PROCESS_ACCESS: u32 = 0x0001;

    /// Admitted ceilings for a Host-owned outer kill domain Job Object. They come
    /// from the owner-facing constructor, so no test Job exists without them.
    fn admitted_outer_limits() -> JobObjectLimits {
        JobObjectLimits::require_admitted_job_limits(Some(268_435_456), Some(4), Some(40))
            .unwrap_or_else(|error| panic!("admitted outer limits failed: {error}"))
    }

    /// Admitted ceilings for the single-process per-generation Job a Module child
    /// is assigned to.
    fn admitted_generation_limits() -> JobObjectLimits {
        JobObjectLimits::require_admitted_job_limits(Some(268_435_456), Some(1), Some(40))
            .unwrap_or_else(|error| panic!("admitted generation limits failed: {error}"))
    }

    /// One fresh Host-owned outer kill domain Job Object name per call, so no two
    /// launches in this module can resolve to the same kernel object.
    fn fresh_outer_name(domain: OuterKillDomain) -> JobObjectIdentity {
        let sequence = JOB_OBJECT_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        JobObjectIdentity::new(format!(
            "Local\\Eliot-Host-{}-a1a3-{}-{sequence}",
            domain.label(),
            std::process::id()
        ))
        .unwrap_or_else(|error| panic!("outer Job name failed: {error}"))
    }

    /// One fresh per-generation Job Object name per call. It is deliberately not
    /// a Host-owned outer name: nesting must never mint a second kill domain.
    fn fresh_generation_name() -> JobObjectIdentity {
        let sequence = JOB_OBJECT_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        JobObjectIdentity::new(format!(
            "Local\\Eliot-P04-a1a3-generation-{}-{sequence}",
            std::process::id()
        ))
        .unwrap_or_else(|error| panic!("generation Job name failed: {error}"))
    }

    /// The CURRENT member PIDs the kernel reports for one named Job Object, read
    /// by opening that exact object. This is live membership, not a value any
    /// launcher wrote.
    fn kernel_job_members(job_name: &str) -> Result<Vec<u32>, WindowsAdapterError> {
        let mut wide = std::os::windows::ffi::OsStrExt::encode_wide(std::ffi::OsStr::new(job_name))
            .collect::<Vec<_>>();
        wide.push(0);
        // SAFETY: `wide` is NUL-terminated; the returned handle is closed below.
        let handle = unsafe { OpenJobObjectW(JOB_OBJECT_QUERY_ACCESS, 0, wide.as_ptr()) };
        if handle.is_null() {
            return Err(super::windows_adapter_from_io(
                &std::io::Error::last_os_error(),
            ));
        }
        // SAFETY: `handle` is the live owned handle `OpenJobObjectW` returned.
        let members =
            job_process_ids(handle).map_err(|error| super::windows_adapter_from_io(&error));
        // SAFETY: `handle` is owned by this scope and is closed exactly once.
        unsafe { CloseHandle(handle) };
        members
    }

    /// Asks the kernel whether THIS process is a member of one exact named Job
    /// Object. The handle is reopened for the question, so the answer is about
    /// the kernel's current membership and not about any name prefix.
    fn this_process_is_in_job(job_name: &str) -> Result<bool, WindowsAdapterError> {
        let mut wide = std::os::windows::ffi::OsStrExt::encode_wide(std::ffi::OsStr::new(job_name))
            .collect::<Vec<_>>();
        wide.push(0);
        // SAFETY: `wide` is NUL-terminated; the returned handle is closed below.
        let job = unsafe { OpenJobObjectW(JOB_OBJECT_QUERY_ACCESS, 0, wide.as_ptr()) };
        if job.is_null() {
            return Err(super::windows_adapter_from_io(
                &std::io::Error::last_os_error(),
            ));
        }
        let mut member = 0;
        // SAFETY: both handles are live and `member` is a live out pointer for
        // the exact documented `BOOL`. `GetCurrentProcess` and `IsProcessInJob`
        // are both called inside this one block.
        let answered = unsafe { IsProcessInJob(GetCurrentProcess(), job, &raw mut member) };
        // SAFETY: `job` is owned by this scope and is closed exactly once.
        unsafe { CloseHandle(job) };
        if answered == 0 {
            return Err(super::windows_adapter_from_io(
                &std::io::Error::last_os_error(),
            ));
        }
        Ok(member != 0)
    }

    /// Places THIS process inside one named Job Object and returns only if the
    /// kernel confirms the membership. This is what a Host-owned Kernel launcher
    /// looks like, and it is the precondition a nested launch re-checks at its
    /// effect boundary.
    fn place_this_process_in_job(job_name: &str) -> Result<(), WindowsAdapterError> {
        let mut wide = std::os::windows::ffi::OsStrExt::encode_wide(std::ffi::OsStr::new(job_name))
            .collect::<Vec<_>>();
        wide.push(0);
        // SAFETY: `wide` is NUL-terminated; the returned handle is closed below.
        let job = unsafe { OpenJobObjectW(JOB_OBJECT_ASSIGN_PROCESS_ACCESS, 0, wide.as_ptr()) };
        if job.is_null() {
            return Err(super::windows_adapter_from_io(
                &std::io::Error::last_os_error(),
            ));
        }
        // SAFETY: this process always exists, and the open exists to assign it.
        let process =
            unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, std::process::id()) };
        if process.is_null() {
            // SAFETY: `job` is owned by this scope and closed exactly once.
            unsafe { CloseHandle(job) };
            return Err(super::windows_adapter_from_io(
                &std::io::Error::last_os_error(),
            ));
        }
        // SAFETY: both handles are live owned handles for the exact documented
        // call; the result is checked rather than ignored.
        let assigned = unsafe { AssignProcessToJobObject(job, process) };
        let failure = if assigned == 0 {
            Some(super::windows_adapter_from_io(
                &std::io::Error::last_os_error(),
            ))
        } else {
            None
        };
        // SAFETY: both handles are owned by this scope and closed exactly once.
        unsafe {
            CloseHandle(process);
            CloseHandle(job);
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// A spec whose child reports its own PID to `marker_path` as its first act
    /// after resume and then stays alive, so that PID is observable while the
    /// process is a live member of both Jobs.
    fn reporting_child_spec(
        marker_path: &std::path::Path,
        working_directory: &std::path::Path,
    ) -> SuspendedLaunchSpec {
        let image =
            std::env::current_exe().unwrap_or_else(|error| panic!("current image: {error}"));
        SuspendedLaunchSpec::new(
            image,
            vec![
                "--exact".into(),
                "process_job::a1_a3_aud3_launch_domain_tests::reporting_child".into(),
                "--nocapture".into(),
            ],
            working_directory,
            vec![(
                std::ffi::OsString::from("ELIOT_A1A3_MARKER"),
                marker_path.as_os_str().to_owned(),
            )],
        )
        .unwrap_or_else(|error| panic!("launch spec failed: {error}"))
    }

    /// The child the Module launch starts. It is itself a `#[test]` so this test
    /// binary can host it, and it does nothing unless this module put the marker
    /// variable into its explicit environment block.
    #[test]
    fn reporting_child() {
        if let Some(marker) = std::env::var_os("ELIOT_A1A3_MARKER") {
            let _ = std::fs::write(marker, format!("{}", std::process::id()));
            std::thread::sleep(std::time::Duration::from_mins(2));
        }
    }

    /// Waits for a launched child to publish its own PID and returns it.
    fn reported_pid(marker_path: &std::path::Path) -> u32 {
        for _ in 0..300 {
            if let Ok(text) = std::fs::read_to_string(marker_path)
                && let Ok(pid) = text.trim().parse::<u32>()
            {
                return pid;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("the launched child never published its PID");
    }

    /// Whether the kernel still holds a live process with this PID.
    fn process_is_gone(pid: u32) -> bool {
        // SAFETY: a query-only open of an existing PID; a null handle means the
        // process no longer exists for this caller.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return true;
        }
        // SAFETY: `handle` is the fresh owned process handle opened above, and a
        // zero-timeout wait on it cannot block.
        let alive = unsafe { WaitForSingleObject(handle, 0) } != WAIT_TIMEOUT;
        // SAFETY: `handle` is owned by this scope and is closed exactly once.
        unsafe { CloseHandle(handle) };
        !alive
    }

    /// A per-test scratch directory. Every name in it is sequence-scoped, so two
    /// concurrent test threads never share one.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let sequence = JOB_OBJECT_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "eliot-a1a3-{tag}-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root)
            .unwrap_or_else(|error| panic!("scratch root failed: {error}"));
        root
    }

    /// Launches one live child into its own per-generation Job and returns it
    /// running, together with the PID it published itself.
    fn launch_reporting_child(
        marker: &std::path::Path,
        root: &std::path::Path,
    ) -> (super::RunningJobChild<()>, u32) {
        let child = SuspendedJobChild::spawn_named_with_limits(
            reporting_child_spec(marker, root),
            fresh_generation_name(),
            admitted_generation_limits(),
        )
        .unwrap_or_else(|error| panic!("child launch failed: {error}"))
        .validate::<(), &'static str, _>(|_| Ok(()))
        .unwrap_or_else(|_| unreachable!())
        .resume()
        .unwrap_or_else(|error| panic!("child resume failed: {error}"));
        let pid = reported_pid(marker);
        assert_eq!(pid, child.evidence().process().process_id);
        (child, pid)
    }

    /// A1: Kernel and Watchdog are in separate outer kill domains, a Module child
    /// belongs to the Host-owned Kernel Job AND to its assigned generation Job,
    /// and closing the Kernel outer Job kills Kernel descendants but not Watchdog.
    ///
    /// The inspected objects are live kernel objects, not values this test wrote:
    /// the kernel member list of the two exact outer Job Objects, the kernel
    /// member list of the Module child's generation Job, and the live
    /// process-existence answer for each actual child PID. The test fails if a
    /// descendant is not where it must be, if the two domains report a shared
    /// member, if closing the Kernel outer Job spares a Kernel descendant, or if
    /// that same close kills the Watchdog descendant.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one inspection covers nesting, domain separation, and the kill-on-close boundary"
    )]
    fn kernel_and_watchdog_are_separate_outer_kill_domains_and_closing_kernel_spares_watchdog() {
        let root = scratch("kernel-vs-watchdog");
        let launch_report = root.join("launch-report");
        let watchdog_marker = root.join("watchdog");

        // The Host-owned Kernel outer Job Object, created by this test with its
        // own object-manager name and admitted ceilings.
        let kernel_outer = JobObject::new_named_outer_kill_on_close_with_limits(
            OuterKillDomain::Kernel,
            fresh_outer_name(OuterKillDomain::Kernel),
            admitted_outer_limits(),
        )
        .unwrap_or_else(|error| panic!("Kernel outer Job creation failed: {error}"));
        let kernel_outer_name = kernel_outer.identity().name().to_owned();
        assert!(
            JobObjectIdentity::new(kernel_outer_name.clone())
                .unwrap_or_else(|error| panic!("Kernel outer identity failed: {error}"))
                .is_host_outer_kill_domain_name(),
            "the Kernel outer Job must be a Host-owned outer kill domain"
        );

        // The Kernel launcher. It is created with `std::process::Command`, so it
        // starts outside every Job, then places itself inside the Host Kernel
        // outer Job and launches the Module child through the nested launch API.
        // It reports the Module child's real PID and the generation Job the
        // platform really assigned, then holds both Job handles open so the
        // child stays alive until this test closes the outer Job.
        let mut launcher = std::process::Command::new(
            std::env::current_exe().unwrap_or_else(|error| panic!("current image: {error}")),
        )
        .arg("--exact")
        .arg("process_job::a1_a3_aud3_launch_domain_tests::kernel_domain_launcher")
        .arg("--nocapture")
        .env("ELIOT_A1A3_KERNEL_OUTER_JOB", &kernel_outer_name)
        .env("ELIOT_A1A3_LAUNCH_REPORT", &launch_report)
        .current_dir(&root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("Kernel launcher spawn failed: {error}"));
        let launcher_pid = launcher.id();
        let (module_pid, generation_name) = read_launch_report(&launch_report);

        // THE MODULE CHILD IS IN BOTH JOBS. Its generation Job is nested inside
        // the Host-owned Kernel outer Job, so the kernel lists the same live PID
        // as a member of each of the two exact named objects.
        let generation_members = kernel_job_members(&generation_name)
            .unwrap_or_else(|error| panic!("generation Job readback failed: {error}"));
        assert!(
            generation_members.contains(&module_pid),
            "the Module child must belong to its assigned generation Job, observed \
             {generation_members:?}"
        );
        let kernel_members = kernel_job_members(&kernel_outer_name)
            .unwrap_or_else(|error| panic!("Host-owned Kernel Job readback failed: {error}"));
        assert!(
            kernel_members.contains(&module_pid),
            "the Module child must belong to the Host-owned Kernel Job, observed {kernel_members:?}"
        );
        assert!(
            kernel_members.contains(&launcher_pid),
            "the Kernel launcher itself must be inside the Host-owned Kernel Job"
        );

        // The Watchdog branch: its own Host-owned outer kill domain Job Object,
        // launched by this contour, which is not inside the Kernel one.
        let watchdog_child = SuspendedJobChild::spawn_named_host_outer_kill_domain(
            reporting_child_spec(&watchdog_marker, &root),
            fresh_outer_name(OuterKillDomain::Watchdog),
            admitted_generation_limits(),
        )
        .unwrap_or_else(|error| panic!("Watchdog child launch failed: {error}"))
        .validate::<(), &'static str, _>(|_| Ok(()))
        .unwrap_or_else(|_| unreachable!())
        .resume()
        .unwrap_or_else(|error| panic!("Watchdog child resume failed: {error}"));
        let watchdog_outer_name = watchdog_child.evidence().job_identity().name().to_owned();
        let watchdog_pid = reported_pid(&watchdog_marker);
        assert_eq!(watchdog_pid, watchdog_child.evidence().process().process_id);

        // SEPARATE OUTER KILL DOMAINS. Each outer Job lists its own live
        // descendants and never the other domain's.
        let kernel_members = kernel_job_members(&kernel_outer_name)
            .unwrap_or_else(|error| panic!("Host-owned Kernel Job readback failed: {error}"));
        assert!(
            !kernel_members.contains(&watchdog_pid),
            "Kernel and Watchdog must not share one child-kill domain"
        );
        assert!(
            !kernel_members.contains(&launcher_pid),
            "the Watchdog launch must not land inside the Host-owned Kernel Job"
        );
        let watchdog_members = kernel_job_members(&watchdog_outer_name)
            .unwrap_or_else(|error| panic!("Watchdog outer Job readback failed: {error}"));
        assert!(
            watchdog_members.contains(&watchdog_pid),
            "the Watchdog descendant must be in the Watchdog outer Job, observed {watchdog_members:?}"
        );
        assert!(
            !watchdog_members.contains(&module_pid),
            "Kernel and Watchdog must not share one child-kill domain"
        );

        // CLOSE THE KERNEL OUTER KILL DOMAIN. This is the acceptance boundary:
        // releasing its sole owning handle must terminate the Kernel descendants
        // and leave the Watchdog descendant running.
        drop(kernel_outer);
        let mut kernel_dead = false;
        for _ in 0..300 {
            if process_is_gone(module_pid) && process_is_gone(launcher_pid) {
                kernel_dead = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            kernel_dead,
            "closing the Host-owned Kernel Job must terminate the Kernel descendants \
             {module_pid} and {launcher_pid}"
        );
        assert!(
            !process_is_gone(watchdog_pid),
            "closing the Host-owned Kernel Job must NOT terminate the Watchdog descendant \
             {watchdog_pid}"
        );
        // The closed outer Job Object is gone from the object manager, while the
        // Watchdog outer Job Object is still there and still holds its member.
        assert!(
            kernel_job_members(&kernel_outer_name).is_err(),
            "the closed Host-owned Kernel Job must no longer exist"
        );
        let survivors = kernel_job_members(&watchdog_outer_name)
            .unwrap_or_else(|error| panic!("Watchdog outer Job must survive: {error}"));
        assert!(
            survivors.contains(&watchdog_pid),
            "the Watchdog outer Job must still hold its member, observed {survivors:?}"
        );
        let _ = launcher.wait();
        watchdog_child
            .terminate(0xE1_50)
            .unwrap_or_else(|error| panic!("Watchdog cleanup failed: {error}"));
        assert!(process_is_gone(watchdog_pid));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Waits for the Kernel launcher to publish what the nested launch actually
    /// did, and returns the Module child's PID and its generation Job name.
    fn read_launch_report(report_path: &std::path::Path) -> (u32, String) {
        for _ in 0..500 {
            if let Ok(text) = std::fs::read_to_string(report_path) {
                let mut lines = text.lines();
                if let (Some(pid), Some(job)) = (lines.next(), lines.next())
                    && let Ok(pid) = pid.trim().parse::<u32>()
                    && !job.trim().is_empty()
                {
                    return (pid, job.trim().to_owned());
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("the Kernel launcher published no launch report");
    }

    /// The process that stands in for a Host-owned Kernel launcher: it enters the
    /// Host Kernel outer Job Object, then launches one Module child through
    /// [`SuspendedJobChild::spawn_nested_in_kernel_outer_kill_domain`] and reports
    /// the real outcome.
    ///
    /// The report is written only after the nested launch returned, so a report
    /// exists only for a launch that really reached that API.
    #[test]
    fn kernel_domain_launcher() {
        let Some(kernel_outer_name) = std::env::var_os("ELIOT_A1A3_KERNEL_OUTER_JOB") else {
            return;
        };
        let kernel_outer_name = kernel_outer_name.to_string_lossy().into_owned();
        let Some(report_path) = std::env::var_os("ELIOT_A1A3_LAUNCH_REPORT") else {
            return;
        };
        let report_path = std::path::PathBuf::from(report_path);
        let root = report_path
            .parent()
            .map_or_else(std::env::temp_dir, std::path::Path::to_path_buf);

        place_this_process_in_job(&kernel_outer_name).unwrap_or_else(|error| {
            panic!("the launcher could not enter the Host-owned Kernel Job: {error}")
        });
        let launcher_identity = inspect_process_identity(std::process::id())
            .unwrap_or_else(|error| panic!("launcher identity read failed: {error}"));
        let outer_binding = RecoverableJobBinding {
            job: JobObjectIdentity::new(kernel_outer_name.clone())
                .unwrap_or_else(|error| panic!("Kernel outer identity failed: {error}")),
            root: ProcessObservation {
                executable: file_identity(std::path::Path::new(&launcher_identity.image_path))
                    .unwrap_or_else(|error| panic!("launcher image read failed: {error}")),
                process: launcher_identity,
            },
        };

        let sequence = JOB_OBJECT_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let generation_name = JobObjectIdentity::new(format!(
            "Local\\Eliot-P04-a1a3-generation-{}-{sequence}",
            std::process::id()
        ))
        .unwrap_or_else(|error| panic!("generation Job name failed: {error}"));
        let marker = root.join("module");
        let child = SuspendedJobChild::spawn_nested_in_kernel_outer_kill_domain(
            reporting_child_spec(&marker, &root),
            generation_name.clone(),
            admitted_generation_limits(),
            outer_binding,
        )
        .unwrap_or_else(|error| panic!("the nested Module launch failed: {error}"));
        let child_pid = child.id();
        // The kernel's own answers, read from the two exact named objects.
        let generation_members = kernel_job_members(generation_name.name())
            .unwrap_or_else(|error| panic!("generation readback failed: {error}"));
        let outer_members = kernel_job_members(&kernel_outer_name)
            .unwrap_or_else(|error| panic!("outer readback failed: {error}"));
        assert!(
            generation_members.contains(&child_pid),
            "the still-suspended child must be in its generation Job, observed \
             {generation_members:?}"
        );
        assert!(
            outer_members.contains(&child_pid),
            "the still-suspended child must be in the Host-owned Kernel Job, observed \
             {outer_members:?}"
        );
        let running = child
            .validate::<(), &'static str, _>(|_| Ok(()))
            .unwrap_or_else(|_| unreachable!())
            .resume()
            .unwrap_or_else(|error| panic!("the launcher could not resume its child: {error}"));
        assert_eq!(reported_pid(&marker), child_pid);
        // Report the real outcome, then hold both Job handles open. The test
        // closes the outer Job, which is what must terminate this child.
        std::fs::write(
            &report_path,
            format!("{child_pid}\n{}\n", generation_name.name()),
        )
        .unwrap_or_else(|error| panic!("the launcher could not publish its report: {error}"));
        std::thread::sleep(std::time::Duration::from_mins(2));
        drop(running);
    }

    /// Builds a durable binding naming `job_name` whose root is a live member of
    /// that exact Job Object, and proves the binding reopens against it.
    ///
    /// The root is a real launched process whose identity is read back from the
    /// kernel, so this binding is not a self-consistent value: reopening it is
    /// the kernel agreeing that the named Job holds that exact process.
    fn live_root_binding(
        job: &JobObject,
        root: &std::path::Path,
        tag: &str,
    ) -> RecoverableJobBinding {
        let marker = root.join(format!("{tag}-root"));
        let (_, member_pid) = launch_reporting_child(&marker, root);
        job.assign_process(member_pid)
            .unwrap_or_else(|error| panic!("root assignment into {tag} Job failed: {error}"));
        let members = kernel_job_members(job.identity().name())
            .unwrap_or_else(|error| panic!("{tag} Job readback failed: {error}"));
        assert!(
            members.contains(&member_pid),
            "{tag} Job must hold its own live member, observed {members:?}"
        );
        let process = inspect_process_identity(member_pid)
            .unwrap_or_else(|error| panic!("{tag} root identity read failed: {error}"));
        let executable = file_identity(std::path::Path::new(&process.image_path))
            .unwrap_or_else(|error| panic!("{tag} root image read failed: {error}"));
        RecoverableJobBinding {
            job: job.identity().clone(),
            root: ProcessObservation {
                process,
                executable,
            },
        }
    }

    /// AUD3 at the platform effect boundary: the launch tuple's exact outer kill
    /// domain binding is re-checked against the CURRENT owning handles and the
    /// launching process before the child may run, so a binding that names a live
    /// Host-owned Kernel Job the launcher does not belong to is refused with no
    /// child created.
    ///
    /// The refusal happens only for real reasons here: the Job is a genuine
    /// Host-owned Kernel outer kill domain Job Object with a genuine live root
    /// member, so it reopens successfully. The only remaining discriminator is the
    /// launcher's own membership, which is exactly the fact AUD3 asks to be
    /// rechecked at the boundary. The test fails if such a launch is accepted, or
    /// if the refusal left a running child behind.
    #[test]
    fn nested_launch_refuses_a_kernel_outer_job_this_launcher_is_not_inside() {
        let root = scratch("foreign-kernel-outer");
        let marker = root.join("never-started");

        // A real, live Host-owned Kernel outer kill domain Job Object holding a
        // real live member, so the presented binding reopens cleanly.
        let foreign = JobObject::new_named_outer_kill_on_close_with_limits(
            OuterKillDomain::Kernel,
            fresh_outer_name(OuterKillDomain::Kernel),
            admitted_outer_limits(),
        )
        .unwrap_or_else(|error| panic!("foreign Kernel outer Job creation failed: {error}"));
        let binding = live_root_binding(&foreign, &root, "foreign");
        let reopened = super::RecoverableJobObject::open(binding.clone())
            .unwrap_or_else(|error| panic!("the foreign Kernel binding did not reopen: {error}"));
        assert_eq!(reopened.identity().name(), binding.job_identity().name());
        drop(reopened);
        assert!(
            !this_process_is_in_job(foreign.identity().name())
                .unwrap_or_else(|error| panic!("Kernel membership read failed: {error}")),
            "this contour must not be inside the outer kill domain it presents"
        );

        assert_eq!(
            SuspendedJobChild::spawn_nested_in_kernel_outer_kill_domain(
                reporting_child_spec(&marker, &root),
                fresh_generation_name(),
                admitted_generation_limits(),
                binding,
            )
            .err(),
            Some(WindowsAdapterError::IdentityMismatch),
            "a Kernel outer Job this launcher is not inside must be refused"
        );
        assert!(
            !marker.exists(),
            "a refused nested launch must not have started any child"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A3: launch fails visibly when required Job nesting cannot be verified.
    ///
    /// The visible failure is the typed refusal the launch API returns, and this
    /// asserts the EXACT refusal kind for two nestings that cannot be verified: an
    /// outer binding in the Watchdog kill domain, and an outer binding naming a
    /// per-generation Job that is no outer kill domain at all. Both must be
    /// refused before any child exists, which the marker file proves: a launched
    /// child publishes that file as its first act, so an absent marker is
    /// evidence that no child ran, not merely evidence that no assertion looked.
    ///
    /// The test fails if either launch silently degrades into an uncontained one,
    /// if the refusal is not the typed `IdentityMismatch`, or if a child is left
    /// running behind a refusal.
    #[test]
    fn unverifiable_job_nesting_is_a_visible_refusal_before_any_child_runs() {
        let root = scratch("nesting-refusal");
        let marker = root.join("never-started");

        // The Watchdog kill domain's own live Job Object. It is a real outer kill
        // domain Job with a real live root, so it is refused for the domain and
        // not for want of a real object.
        let watchdog_domain = JobObject::new_named_outer_kill_on_close_with_limits(
            OuterKillDomain::Watchdog,
            fresh_outer_name(OuterKillDomain::Watchdog),
            admitted_outer_limits(),
        )
        .unwrap_or_else(|error| panic!("Watchdog outer Job creation failed: {error}"));
        let watchdog_binding = live_root_binding(&watchdog_domain, &root, "watchdog");
        assert_eq!(
            SuspendedJobChild::spawn_nested_in_kernel_outer_kill_domain(
                reporting_child_spec(&marker, &root),
                fresh_generation_name(),
                admitted_generation_limits(),
                watchdog_binding,
            )
            .err(),
            Some(WindowsAdapterError::IdentityMismatch),
            "the Watchdog kill domain must never be accepted as the Kernel outer binding"
        );
        assert!(!marker.exists(), "the refused launch left a child behind");

        // A per-generation Job name is not a Host-owned outer kill domain at all,
        // so it is refused for the same visible reason and still starts nothing.
        let nested_only = JobObject::new_named_kill_on_close_with_limits(
            fresh_generation_name(),
            admitted_outer_limits(),
        )
        .unwrap_or_else(|error| panic!("nested-only Job creation failed: {error}"));
        let nested_only_binding = live_root_binding(&nested_only, &root, "nested-only");
        assert_eq!(
            SuspendedJobChild::spawn_nested_in_kernel_outer_kill_domain(
                reporting_child_spec(&marker, &root),
                fresh_generation_name(),
                admitted_generation_limits(),
                nested_only_binding,
            )
            .err(),
            Some(WindowsAdapterError::IdentityMismatch),
            "a per-generation Job name must never be accepted as an outer kill domain"
        );
        assert!(
            !marker.exists(),
            "the second refused launch left a child behind"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Keeps the process-identity import honest for the PID used above.
    const _: fn() -> u32 = || unsafe { GetCurrentProcessId() };
}
