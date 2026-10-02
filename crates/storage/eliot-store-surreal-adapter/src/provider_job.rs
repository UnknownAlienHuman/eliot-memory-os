//! The one launch path that ends an owned `SurrealDB` provider with its owner
//! (#1888, package K-STORE).
//!
//! An owned provider that is not inside a Windows Job Object outlives its
//! owner: when the owner ends for any reason that skips Rust destructors —
//! `TerminateProcess`, `timeout`, `panic = "abort"`, a runner kill — no
//! `Drop` and no `kill_on_drop` ever runs, and the server keeps holding its port
//! and its data root (REPORT
//! `cleanup/runs/surreal-leak-20261001-2029/REPORT.md`, sections 1 and 4).
//!
//! `I1.6` (`docs/architecture/I01-06-windows-isolation.md`) names the
//! mechanism: "all child processes enter the applicable Windows Job Object"
//! and "the process tree receives kill-on-close at its outer ownership
//! boundary". The kill domain itself — the Host-owned distinct outer Jobs for
//! Kernel, Watchdog and Store — is NOT this package and stays open in
//! `REMAINING.md`; this file only makes the store provider child a member of a
//! kill-on-close Job whose handle its owner holds for the child's whole life.
//!
//! There is exactly one Job Object implementation in this repository:
//! [`eliot_platform_windows::JobObject`]. This module holds that value and
//! nothing else. It writes no Win32 call of its own and defines no second Job
//! wrapper: `new_kill_on_close` creates and configures the Job, and
//! `assign_process` performs the assignment and returns the observed process
//! identity.

use std::ffi::OsString;

use eliot_platform_windows::{JobObject, ProcessIdentity, WindowsAdapterError};

use crate::error::AdapterError;

/// The retained kill-on-close Job Object handle of one owned provider.
///
/// Holding this value for the child's whole life is what makes the provider
/// end with its owner: `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` is evaluated by the
/// kernel when the sole owning handle is closed, and Windows closes that handle
/// when the owning process ends for any reason. Dropping the value is the
/// explicit in-process equivalent.
pub struct ProviderKillDomain {
    job: JobObject,
    admitted: Option<(u32, ProcessIdentity)>,
}

impl ProviderKillDomain {
    /// Creates the kill-on-close Job Object for one provider launch.
    ///
    /// Refusal is the outcome when Windows will not produce the Job: there is
    /// no uncontained launch, so nothing may proceed to `spawn()`.
    ///
    /// # Errors
    /// Returns [`AdapterError::LaunchJobAssignmentFailed`] carrying the typed
    /// platform error when Job creation or kill-on-close configuration fails.
    pub fn create() -> Result<Self, AdapterError> {
        let job = JobObject::new_kill_on_close()
            .map_err(|cause| AdapterError::LaunchJobAssignmentFailed { cause })?;
        Ok(Self {
            job,
            admitted: None,
        })
    }

    /// Admits `process_id` into this Job and retains it for that child's life.
    ///
    /// # Errors
    /// Returns [`AdapterError::LaunchJobAssignmentFailed`] carrying the typed
    /// platform error when Windows refuses the assignment. The caller must not
    /// fall back to an unassigned launch.
    pub fn admit(mut self, process_id: u32) -> Result<Self, AdapterError> {
        let identity = self
            .job
            .assign_process(process_id)
            .map_err(|cause| AdapterError::LaunchJobAssignmentFailed { cause })?;
        self.admitted = Some((process_id, identity));
        Ok(self)
    }

    /// Builds the retained kill domain for one already-spawned provider child.
    ///
    /// This is the whole contract in one call: the Job exists, the spawned
    /// child is inside it, and the returned handle outlives the child.
    ///
    /// # Errors
    /// Returns [`AdapterError::LaunchJobAssignmentFailed`] carrying the typed
    /// platform error when the Job cannot be created or the child cannot be
    /// assigned. The child has already been launched when this fails, so the
    /// caller must terminate it rather than leave it running.
    pub fn admit_spawned(child_process_id: Option<u32>) -> Result<Self, AdapterError> {
        let process_id = child_process_id.filter(|id| *id != 0).ok_or_else(|| {
            AdapterError::Config(
                "canonical provider child PID is unavailable before job admission".to_owned(),
            )
        })?;
        Self::create()?.admit(process_id)
    }

    /// Returns the admitted provider process id, or `None` before admission.
    #[must_use]
    pub fn process_id(&self) -> Option<u32> {
        self.admitted.map(|(process_id, _)| process_id)
    }

    /// Returns the exact process identity Windows re-observed through
    /// `assign_process`, or `None` before admission.
    #[must_use]
    pub fn admitted_identity(&self) -> Option<&ProcessIdentity> {
        self.admitted.as_ref().map(|(_, identity)| identity)
    }
}

/// The admitted provider child and the kill domain that must outlive it.
///
/// Dropping this value closes the Job handle, and closing the last handle to a
/// kill-on-close Job terminates every process assigned to it. That is the
/// in-process end-of-owner path; the cross-process one is the kernel closing
/// the handle when the owner itself ends.
pub struct ProviderKillOnCloseLease {
    _kill_domain: ProviderKillDomain,
}

/// Installs the single launch path: spawn, then admit, with no unassigned
/// fallback, and return the retained lease.
///
/// The Job is created before `spawn()` so a Job refusal costs nothing, and the
/// child is assigned immediately after `spawn()` and before the provider is
/// used, so there is no window in which a running provider is uncontained.
/// `spawn` supplies the platform-specific `spawn()`/`id()` pair so one path
/// serves both the Tokio-backed adapter and the `std`-backed test fixtures.
///
/// # Errors
///
/// Returns [`AdapterError::LaunchJobAssignmentFailed`] carrying the typed
/// platform error when the Job cannot be created or the spawned child cannot be
/// assigned. The one non-typed stage, process creation itself, reports the
/// existing [`AdapterError::Config`]. `refuse` runs only after the launch has
/// been abandoned, so a refused launch terminates the child it already created
/// instead of leaving a provider behind.
pub fn spawn_provider_kill_on_close<C, S, F, X>(
    spawn: S,
    child_process_id: F,
    refuse: X,
) -> Result<(C, ProviderKillOnCloseLease), AdapterError>
where
    S: FnOnce() -> std::io::Result<C>,
    F: FnOnce(&C) -> Option<u32>,
    X: FnOnce(&mut C),
{
    let kill_domain = ProviderKillDomain::create()?;
    let mut child = spawn()
        .map_err(|_| AdapterError::Config("canonical provider process launch failed".to_owned()))?;
    match ProviderKillDomain::admit_spawned(child_process_id(&child)) {
        Ok(admitted) => Ok((
            child,
            ProviderKillOnCloseLease {
                _kill_domain: admitted,
            },
        )),
        Err(cause) => {
            // The launch is refused, so the already-created child must not
            // outlive this call. Terminate and reap it before surfacing the
            // typed refusal: an ignored failure here is exactly the orphan this
            // package exists to remove.
            refuse(&mut child);
            Err(cause)
        }
    }
}

/// Launches one fixture-owned provider through [`spawn_provider_kill_on_close`].
///
/// Every test starter in this repository that runs its own `surreal.exe`
/// bootstrap — the kernel S-CONC harness, the adapter transaction-allocation
/// suite, and every `prepare_initial_root_user` fixture — routes through this
/// one function rather than through its own `Command::spawn()`. There is no
/// second launch path to keep in step and no fixture that can leak by omission.
///
/// # Errors
///
/// Returns [`AdapterError::LaunchJobAssignmentFailed`] carrying the typed
/// platform error when the Job cannot be created or the spawned child cannot be
/// assigned, after the spawned child has been killed and reaped.
pub fn launch_fixture_provider<C, S, F, X>(
    spawn: S,
    child_process_id: F,
    refuse: X,
) -> Result<(C, ProviderKillOnCloseLease), AdapterError>
where
    S: FnOnce() -> std::io::Result<C>,
    F: FnOnce(&C) -> Option<u32>,
    X: FnOnce(&mut C),
{
    spawn_provider_kill_on_close(spawn, child_process_id, refuse)
}

/// Terminates and reaps a `std` provider child that a refused launch left
/// running. This is the [`std::process::Child`] form of the refusal step, so
/// every fixture refusal path shares it.
///
/// Both calls are best-effort and deliberately ignore their outcome: the
/// refusal the caller then surfaces is the Job-admission failure, and a kill
/// that Windows already applied is not a second error to report.
pub fn reap_refused_std_child(child: &mut std::process::Child) {
    let _kill_result = child.kill();
    let _wait_result = child.wait();
}

/// The exact child environment block one fixture-owned provider launch uses.
///
/// Fixtures that clear the parent environment must still hand the child the two
/// Windows roots it needs to start, so the shared launch path builds that block
/// once instead of each fixture repeating it.
#[must_use]
pub fn fixture_provider_environment(
    store_temp_root: &str,
    bootstrap_username: &str,
    bootstrap_password: &str,
) -> Vec<(OsString, OsString)> {
    let system_root = std::env::var_os("SystemRoot")
        .map_or_else(|| OsString::from("C:\\Windows"), |value| value.into());
    vec![
        ("SystemRoot".into(), system_root.clone()),
        ("WINDIR".into(), system_root),
        ("TEMP".into(), OsString::from(store_temp_root)),
        ("TMP".into(), OsString::from(store_temp_root)),
        ("SURREAL_USER".into(), OsString::from(bootstrap_username)),
        ("SURREAL_PASS".into(), OsString::from(bootstrap_password)),
    ]
}

/// Projects a refusal onto the exact typed cause that produced it.
///
/// The refusal tests need to observe the platform-adapter error itself, not
/// only the adapter wrapper, so this exposes the typed cause without inventing
/// a second error family.
#[must_use]
pub fn refusal_cause(error: &AdapterError) -> Option<WindowsAdapterError> {
    match error {
        AdapterError::LaunchJobAssignmentFailed { cause } => Some(*cause),
        _ => None,
    }
}
