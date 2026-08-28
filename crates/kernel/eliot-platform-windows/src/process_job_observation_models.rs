//! Immutable Windows Job observation models only.
//!
//! Architecture A5.1, `Reality and observation`, limits ELIOT to bounded
//! observations and models; reality remains external. Implementation I1.6,
//! `Windows isolation`, keeps the Windows Job Object as the isolation and
//! lifecycle boundary. Implementation I2.1, `crate-rich, process-sparse,
//! owner-sparse`, means module or crate membership creates no lifecycle,
//! mutable-state, or authority owner.
//!
//! This child owns immutable Job observation, binding, and history DTOs plus
//! local validation, ordering, and gap semantics only. The parent Windows
//! adapter owns Job Object handles, the OS observation thread, process
//! lifecycle, spawn/suspend/terminate/cancel effects, and authority.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FileIdentity;
use crate::ProcessIdentity;
use crate::WindowsAdapterError;

#[cfg(windows)]
use super::JobObjectIdentity;

#[cfg(windows)]
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessObservation {
    pub(super) process: ProcessIdentity,
    pub(super) executable: FileIdentity,
}

/// Durable raw binding used only to reopen and revalidate one named Job.
///
/// The value is not authority: `RecoverableJobObject::open` must re-observe
/// the exact root identity before returning a live mechanics handle.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverableJobBinding {
    pub(super) job: JobObjectIdentity,
    pub(super) root: ProcessObservation,
}

#[cfg(windows)]
impl RecoverableJobBinding {
    /// Validates only the bounded serialized shape.
    ///
    /// The result is not proof of a live process or Job. Callers must pass the
    /// binding to [`RecoverableJobObject::open`] for fresh kernel revalidation.
    ///
    /// # Errors
    /// Returns `InvalidInput` for malformed Job or root-process identity.
    pub fn validate(&self) -> Result<(), WindowsAdapterError> {
        self.job.validate()?;
        let root = self.root.process();
        let image_length = root.image_path.encode_utf16().count();
        if root.process_id == 0
            || root.start_time_100ns == 0
            || image_length == 0
            || image_length > 32_767
            || root.image_path.chars().any(char::is_control)
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(())
    }

    /// Returns the bound Job Object identity.
    #[must_use]
    pub const fn job_identity(&self) -> &JobObjectIdentity {
        &self.job
    }

    /// Returns the exact root process/image observation.
    #[must_use]
    pub const fn root(&self) -> &ProcessObservation {
        &self.root
    }
}

#[cfg(windows)]
impl ProcessObservation {
    /// Returns the retained-handle process identity.
    #[must_use]
    pub const fn process(&self) -> &ProcessIdentity {
        &self.process
    }

    /// Returns the file-object identity of the observed executable image.
    #[must_use]
    pub const fn executable_file_identity(&self) -> FileIdentity {
        self.executable
    }

    pub(super) fn stable_key(&self) -> String {
        format!(
            "{}:volume:{}:file:{}",
            self.process.stable_key(),
            self.executable.volume_serial_number,
            self.executable.file_index
        )
    }
}

/// Why a Job history cannot be claimed complete.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobObservationGap {
    /// At least one kernel process notification could not be resolved to an
    /// exact retained process/image identity before the process disappeared.
    IdentityCaptureFailed,
}

/// Historical process membership observed from the Job completion port.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobProcessHistory {
    pub(super) processes: Vec<ProcessObservation>,
    pub(super) complete: bool,
    pub(super) job_empty: bool,
    pub(super) capture_gap: Option<JobObservationGap>,
    pub(super) resource_limit_triggered: bool,
}

#[cfg(windows)]
impl JobProcessHistory {
    /// Returns all distinct process identities observed during this Job life.
    #[must_use]
    pub fn processes(&self) -> &[ProcessObservation] {
        &self.processes
    }

    /// Returns whether the historical membership observation is complete.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns whether the Job was observed with zero active members.
    #[must_use]
    pub const fn job_empty(&self) -> bool {
        self.job_empty
    }

    /// Returns the explicit observation gap that prevented completeness.
    #[must_use]
    pub const fn capture_gap(&self) -> Option<JobObservationGap> {
        self.capture_gap
    }

    /// Returns whether the kernel emitted a CPU, memory, or process-count
    /// limit notification for this Job.
    #[must_use]
    pub const fn resource_limit_triggered(&self) -> bool {
        self.resource_limit_triggered
    }
}
