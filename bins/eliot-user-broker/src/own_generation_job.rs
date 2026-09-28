//! The Job Object this broker process generation creates and owns for itself.
//!
//! `I1.6` (`docs/architecture/I01-06-windows-isolation.md`, "User-session
//! isolation") states that `eliot-user-broker.exe` runs "under the interactive
//! user's token, in its own Job Object and immutable generation". The broker
//! is not a Host-owned branch: it is neither the Host Kernel, Store, nor
//! Watchdog kill domain, so this Job Object is created through the plain nested
//! constructor and its `outer_kill_domain` stays `None`. A nested Job Object
//! never mints a second outer kill domain, and `Local\Eliot-UserBroker-…` is
//! not a `Local\Eliot-Host-…` name, so this contour can never be mistaken for
//! a Host-owned outer one.
//!
//! ## What this contour contains
//!
//! This Job Object contains this broker process generation AND, by Windows
//! job-membership inheritance, every process this generation creates without
//! breakaway. It installs no `JOB_OBJECT_LIMIT_BREAKAWAY_OK`, and nothing in
//! this workspace passes `CREATE_BREAKAWAY_FROM_JOB` to `CreateProcessW`, so
//! membership is inherited by every child and cannot be declined. The
//! repository's own nesting probe depends on exactly that inheritance: it
//! requires a child to remain a member of the outer job after being assigned
//! to a nested one.
//!
//! The broker's launched children additionally sit in their own per-attempt
//! job, which the executor creates fresh as `Local\Eliot-P04-<pid>-<seq>` and
//! nests inside the Host-owned Kernel outer job. Those per-attempt job handles
//! are reached through the `broker` field of the composition, which is declared
//! before the generation job, so declaration-order field drop releases the
//! per-attempt contours first and the generation contour last. Which children
//! belong to which Job Object is the Kernel/ORS registration owner's decision,
//! and nothing here claims it.
//!
//! ## Ownership
//!
//! Creation is exclusive, never a name reuse: the durable name carries this
//! generation's process id and observed start instant, and
//! `JobObject::new_named_kill_on_close` calls `CreateJobObjectW` and refuses
//! `ERROR_ALREADY_EXISTS`, so a generation that finds its own durable name
//! already taken fails closed instead of joining a Job Object some other
//! process created.
//!
//! Exclusive creation is not handle ownership. The job's DACL is
//! `D:P(A;;GA;;;SY)(A;;GA;;;OW)`, so a `LocalSystem` process or another process
//! running as this same user can open that durable name and hold its own
//! handle. This cell therefore owns the handle it created; it does not prove
//! it is the only handle in existence, and while another handle is open the
//! kill-on-close limit does not fire on this handle's release at all.
//!
//! ## What this cell proves
//!
//! That Windows accepted the assignment of this process to the job it had just
//! created, and that the identity Windows re-observed through `assign_process`
//! is the admitted generation. Membership is NOT re-observed afterwards:
//! `JobObject::contains_process` is private to the platform crate and is not
//! called from here.
//!
//! This cell mints no registration, no nonce, and no lease. The
//! `eliot-user-broker.exe` registration and its SID/session/artifact/nonce
//! binding belong to the Kernel/ORS owner, not here.

#![forbid(unsafe_code)]

use eliot_platform_windows::{JobObject, JobObjectIdentity, ordinal_eq_str};

use super::CompositionError;
use super::protected_launch_config::BrokerProcessIdentity;
use crate::BrokerAdmissionRefusal;

/// One broker process generation admitted to the Job Object it created itself.
///
/// The contained `JobObject` is the handle this generation created. Dropping
/// it releases that handle; because this process is a member of the job, that
/// release fires the job's kill-on-close limit and terminates this process
/// inside `drop`. The only way to construct this value is
/// [`create_owned_generation_job`], the only path that both created the job
/// and assigned this process generation to it.
pub(super) struct OwnedGenerationJob {
    /// The handle this generation created for the Job Object it is a member of.
    job: JobObject,
}

impl OwnedGenerationJob {
    /// Returns the durable identity of the Job Object this generation created.
    pub(super) fn identity(&self) -> &JobObjectIdentity {
        self.job.identity()
    }
}

/// Creates the Job Object this broker process generation owns, and assigns
/// this process generation to it.
///
/// The durable name carries the admitted generation — the process id and its
/// observed start instant — so a generation that recycles a process id cannot
/// join the Job Object of the generation that previously held that number, and
/// the name a readiness reader sees is itself bound to this generation rather
/// than to a broker product that outlives it.
///
/// `assign_process` takes only a process id and opens its own process handle
/// internally, then re-observes the process through that handle. The observed
/// start instant and image path are the real signal: `ProcessIdentity`'s
/// `process_id` is the requested number echoed back, not an independent
/// observation. A process id that resolved to a different start instant or a
/// different image means the job is not bound to the process this broker proved
/// it is, and is refused rather than reinterpreted.
///
/// # Startup dependency
///
/// Job creation is an UNCONDITIONAL STARTUP DEPENDENCY of this binary: if
/// Windows refuses to admit this process to the job it just created, the broker
/// does not start at all. That is the intended fail-closed direction for
/// `I1.6`, and it is recorded here because the deployment shapes this must
/// hold for — a broker launched from inside an existing Host job, versus one
/// launched by Explorer or the Task Scheduler — have not been measured.
///
/// # Errors
///
/// Fails closed when the name is not a valid object-manager name, when Windows
/// refuses creation or refuses a name this generation already owns, when
/// Windows refuses to admit this process to the Job Object it just created, or
/// when the assignment resolves to a process other than the admitted
/// generation.
///
/// The typed cause is [`BrokerAdmissionRefusal::GenerationJobUnownable`]. On
/// the composition-start path the binary reports this under its own
/// `BROKER_COMPOSITION_REJECTED` code, so the refusal code is not projected to
/// the wire there.
pub(super) fn create_owned_generation_job(
    process: &BrokerProcessIdentity,
) -> Result<OwnedGenerationJob, CompositionError> {
    // Harmless to fail with the job not yet created: no job exists, so there
    // is nothing to release and nothing to terminate.
    let identity = JobObjectIdentity::new(format!(
        "Local\\Eliot-UserBroker-Generation-{}-{}",
        process.process_id, process.process_start_100ns
    ))
    .map_err(|error| BrokerAdmissionRefusal::GenerationJobUnownable.with_platform(error))?;
    // Harmless to fail here: creation refused, so this generation holds no
    // handle, and a job that was never created has no members to kill.
    let job = JobObject::new_named_kill_on_close(identity)
        .map_err(|error| BrokerAdmissionRefusal::GenerationJobUnownable.with_platform(error))?;
    // Harmless to fail here: the job exists but this process was never made a
    // member, so releasing the handle on the way out terminates nothing.
    let assigned = job
        .assign_process(process.process_id)
        .map_err(|error| BrokerAdmissionRefusal::GenerationJobUnownable.with_platform(error))?;
    if assigned.process_id != process.process_id
        || assigned.start_time_100ns != process.process_start_100ns
        || !ordinal_eq_str(&assigned.image_path, &process.image_path)
    {
        // NOT harmless: this process IS a member now, so returning normally
        // would drop `job` and the kernel would terminate this process inside
        // that `drop`, before the refusal below could reach the wire. The
        // handle is therefore deliberately NOT released by `drop`: it is leaked
        // here and reclaimed by process teardown, after the caller has written
        // the refusal and the process has exited. Nothing is given up by that
        // ordering — the handle still closes with the process, and the job
        // still tears down every other member it inherited on the way out.
        std::mem::forget(job);
        return Err(BrokerAdmissionRefusal::GenerationJobUnownable.with_platform(
            "the Job Object assignment resolved to a process other than the admitted generation",
        ));
    }
    Ok(OwnedGenerationJob { job })
}
