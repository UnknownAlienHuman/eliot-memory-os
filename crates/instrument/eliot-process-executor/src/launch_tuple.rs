//! AUD3 (#1888): one validated launch tuple, bound and re-checked at the
//! platform effect boundary.
//!
//! Comment 5871793301 item 2 governs this module: "In the existing
//! `run_process_start`/executor handoff, carry one validated launch tuple:
//! operation/attempt, owner generation, approved executable/config, execution
//! identity, manifest limits and exact outer/inner Job bindings. Check this
//! tuple again at the platform effect boundary, before resuming executable
//! code. A non-null Job name or a self-consistent serialized binding is not
//! sufficient without the current owning handle/identity check."
//!
//! Two halves, and the second decides the item:
//!
//! 1. **Bound.** [`ValidatedLaunchTuple`] holds the six named elements as one
//!    value. They are not six independent values that happen to travel near
//!    each other: the tuple cannot be constructed without all six, and
//!    [`ValidatedLaunchTuple::bind`] refuses any disagreement among them
//!    before a child is created.
//! 2. **Re-checked.** [`ValidatedLaunchTuple::recheck_before_resume`] compares
//!    the tuple against a FRESH observation of the actual suspended child,
//!    built by the platform layer from its retained kernel handles while that
//!    child is still suspended. The tuple is never compared against its own
//!    copy of itself, and a Job name alone never stands in for a handle read:
//!    the inner-Job element is compared against the Job identity the live Job
//!    handle reports, not against a string the launcher presented. This covers
//!    elements 3 and 6 only; see the per-element verdicts on
//!    [`ValidatedLaunchTuple::recheck_before_resume`] for the four elements
//!    that are bound and carried but NOT re-observed against live state, and
//!    for why.
//!
//! Element provenance is recorded per field below and in each getter's doc.
//! Two elements have no admitted live re-observation and are reported as such
//! rather than filled in: the execution-identity element has no admitted
//! producer ([`ValidatedLaunchTuple::execution_identity`]), and the
//! manifest-limits element is not read back from the live inner Job
//! ([`ValidatedLaunchTuple::recheck_before_resume`]).

use eliot_platform_windows::{
    ExecutionIdentityMode, FileIdentity, JobObjectIdentity, JobObjectLimits, OuterKillDomain,
    RecoverableJobBinding, SuspendedProcessEvidence,
};
use eliot_process::{Generation, ProcessRequest};
use std::path::{Path, PathBuf};

/// The six elements comment 5871793301 item 2 names, bound as one unit.
///
/// Constructed by [`ValidatedLaunchTuple::bind`] in the executor handoff and
/// consumed by [`ValidatedLaunchTuple::recheck_before_resume`] inside P-04's
/// `SuspendedJobChild::validate` closure, which is the last point before
/// `ValidatedSuspendedJobChild::resume` calls `ResumeThread`.
///
/// Refusals stay typed: [`LaunchTupleError`] names which element disagreed
/// with the live observation, and the caller maps it onto its own typed
/// refusal without erasing it into a boolean.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedLaunchTuple {
    /// Element 1: the operation/attempt identity this launch is one attempt of.
    operation_id: eliot_process::OperationId,
    /// Element 2: the owner generation whose admitted manifest supplied the
    /// limits below.
    generation: Generation,
    /// Element 3a: the approved executable, as canonicalized and digest-checked
    /// at the executor handoff.
    approved_executable: PathBuf,
    /// Element 3b: the admitted `executable_sha256` the approval above is
    /// sealed against.
    approved_executable_sha256: String,
    /// Element 4: the declared execution identity for the child.
    ///
    /// See [`Self::execution_identity`]: this is the one element whose admitted
    /// producer is not reachable from this crate today.
    execution_identity: ExecutionIdentityMode,
    /// Element 5: the admitted Module Manifest Job ceilings installed on the
    /// per-attempt inner Job.
    manifest_limits: JobObjectLimits,
    /// Element 6a: the exact Host-owned outer Job binding this launch is
    /// nested inside.
    ///
    /// `None` only on the `#[cfg(test)]` launch seam, which creates a
    /// per-attempt Job with no Host-owned outer Job at all; there is then no
    /// outer binding to observe, and `None` records that fact rather than a
    /// fabricated one. Every production launch takes [`Self::bind`] and carries
    /// `Some`.
    outer_binding: Option<RecoverableJobBinding>,
    /// Element 6b: the exact per-attempt inner Job identity created for this
    /// attempt.
    inner_job: JobObjectIdentity,
}

#[cfg(windows)]
impl ValidatedLaunchTuple {
    /// Binds the six elements of a PROVEN nested Kernel launch as one unit,
    /// before any child is created.
    ///
    /// This is the only constructor a production launch can reach, so no
    /// production path carries a partial tuple. The checks here are the ones
    /// that can be made from the admitted inputs alone; everything that needs a
    /// live kernel read is left to [`Self::recheck_before_resume`], which is
    /// the check the issue requires.
    ///
    /// # Errors
    /// Returns [`LaunchTupleError::Missing`] when the approved executable or
    /// its sealed digest is blank, and [`LaunchTupleError::IdentityMismatch`]
    /// when the outer binding does not name the exact Host-owned Kernel outer
    /// Job this executor launches into.
    pub fn bind(
        request: &ProcessRequest,
        approved_executable: &Path,
        approved_executable_sha256: &str,
        execution_identity: ExecutionIdentityMode,
        manifest_limits: JobObjectLimits,
        outer_binding: RecoverableJobBinding,
        inner_job: JobObjectIdentity,
    ) -> Result<Self, LaunchTupleError> {
        // The nested launch path is the Kernel contour only. A binding naming
        // any other Job -- including a per-attempt nested name, which is not an
        // outer kill domain name -- is refused here rather than reaching
        // `spawn_nested_in_kernel_outer_kill_domain`.
        if !is_kernel_outer_job_name(outer_binding.job_identity().name()) {
            return Err(LaunchTupleError::IdentityMismatch);
        }
        Self::bind_common(
            request,
            approved_executable,
            approved_executable_sha256,
            execution_identity,
            manifest_limits,
            Some(outer_binding),
            inner_job,
        )
    }

    /// Binds the same six elements for a launch that provably has no
    /// Host-owned outer Job.
    ///
    /// Only the `#[cfg(test)]` launch seam is allowed here: it creates the
    /// per-attempt Job directly, with no outer kill domain. Element 6a is then
    /// `None` because there is no outer Job to observe -- not because a check
    /// was skipped. The inner element (6b) and the approved-executable element
    /// are still bound and still re-checked against the live child, so this
    /// seam proves those halves of the re-check on a real launch.
    ///
    /// # Errors
    /// Returns [`LaunchTupleError::Missing`] when the approved executable or
    /// its sealed digest is blank.
    #[cfg(test)]
    pub fn bind_without_outer_job(
        request: &ProcessRequest,
        approved_executable: &Path,
        approved_executable_sha256: &str,
        execution_identity: ExecutionIdentityMode,
        manifest_limits: JobObjectLimits,
        inner_job: JobObjectIdentity,
    ) -> Result<Self, LaunchTupleError> {
        Self::bind_common(
            request,
            approved_executable,
            approved_executable_sha256,
            execution_identity,
            manifest_limits,
            None,
            inner_job,
        )
    }

    /// The single construction body both constructors share.
    ///
    /// # Errors
    /// Returns [`LaunchTupleError::Missing`] when the approved executable or
    /// its sealed digest is blank.
    fn bind_common(
        request: &ProcessRequest,
        approved_executable: &Path,
        approved_executable_sha256: &str,
        execution_identity: ExecutionIdentityMode,
        manifest_limits: JobObjectLimits,
        outer_binding: Option<RecoverableJobBinding>,
        inner_job: JobObjectIdentity,
    ) -> Result<Self, LaunchTupleError> {
        if approved_executable.as_os_str().is_empty()
            || approved_executable_sha256.trim().is_empty()
        {
            return Err(LaunchTupleError::Missing);
        }
        Ok(Self {
            operation_id: request.operation_id().clone(),
            generation: request.generation(),
            approved_executable: approved_executable.to_path_buf(),
            approved_executable_sha256: approved_executable_sha256.to_owned(),
            execution_identity,
            manifest_limits,
            outer_binding,
            inner_job,
        })
    }

    /// Re-checks the bound tuple against the LIVE suspended child, before
    /// resume.
    ///
    /// `evidence` is the platform layer's fresh observation, built from the
    /// retained kernel handles of THIS child and THIS Job Object while the
    /// child is still suspended. Every element compared below is read from
    /// that observation or from a live owning handle; none is compared against
    /// the tuple's own copy of itself.
    ///
    /// Re-checked against the live observation:
    /// - element 3 (approved executable): the evidence's `requested_executable`
    ///   must be this executable, and the evidence's observed image file
    ///   identity must be a non-zero volume/file index.
    /// - element 6 (Job bindings): the evidence's `job_identity`, taken from the
    ///   live per-attempt Job handle this launch created, must be this exact
    ///   inner Job. The outer element is re-asserted to still name the
    ///   Host-owned Kernel outer Job; P-02 independently re-opens that outer
    ///   binding and re-reads its kill-on-close flag and ceilings from the
    ///   kernel inside `spawn_nested_in_kernel_outer_kill_domain`, and
    ///   re-checks this exact child against that live outer handle, before this
    ///   closure is reached.
    ///
    /// Elements 1, 2, 4 and 5 are not re-observed here and are deliberately not
    /// claimed to be:
    /// - elements 1 and 2 (operation/attempt, owner generation) are the
    ///   attempt's own bookkeeping, consumed by the dispatch port in this same
    ///   closure; there is no kernel state to read them back from.
    /// - element 4 (execution identity) is compared against the LIVE token in
    ///   the platform layer, but against the identity that launch RESOLVED, not
    ///   against this tuple's element: the token/SID is not carried on
    ///   [`SuspendedProcessEvidence`], so the tuple cannot take part in that
    ///   comparison. See [`Self::execution_identity`] for the missing producer.
    /// - element 5 (manifest limits) is the one element whose doc previously
    ///   claimed a read-back that does not happen: the per-attempt inner Job is
    ///   created with these ceilings and
    ///   [`SuspendedProcessEvidence::enforced_limits`] reports the value this
    ///   launch passed in, not a re-read of the Job Object
    ///   (`fresh_evidence` sets it from `self.resource_limits`). P-02 reads
    ///   back the OUTER Job's kill-on-close flag and ceilings from the kernel
    ///   (`observed_job_containment` via `attest_created_outer_job` /
    ///   `require_attested_outer_job`), never the inner per-attempt Job. So the
    ///   inner element is bound and carried, and its install is refused closed
    ///   by `SetInformationJobObject` inside `create_named_kill_on_close`
    ///   (a rejected limit fails the Job creation before any child exists),
    ///   but it is NOT verified by re-reading the live inner Job. Reported
    ///   rather than papered over; no re-check was invented to fill the gap.
    ///
    /// # Errors
    /// Returns [`LaunchTupleError::IdentityMismatch`] when the live observation
    /// disagrees with a bound element, and [`LaunchTupleError::Unavailable`]
    /// when the observed image identity is absent, so agreement cannot be
    /// shown.
    pub fn recheck_before_resume(
        &self,
        evidence: &SuspendedProcessEvidence,
    ) -> Result<(), LaunchTupleError> {
        self.compare_observed(
            evidence.job_identity(),
            evidence.requested_executable(),
            evidence.executable_file_identity(),
        )
    }

    /// The comparison `recheck_before_resume` performs, over the values read
    /// from the live observation.
    ///
    /// Split out so the refusal rules are provable without a live kernel: the
    /// three arguments are exactly what `SuspendedProcessEvidence` reports for
    /// THIS child and THIS Job, and `recheck_before_resume` is the only caller
    /// that supplies them from a real observation.
    ///
    /// # Errors
    /// Returns [`LaunchTupleError::IdentityMismatch`] when the observed Job or
    /// executable is not the bound one, or the bound outer element is not this
    /// Host-owned Kernel outer Job; returns [`LaunchTupleError::Unavailable`]
    /// when no image file identity was observed.
    fn compare_observed(
        &self,
        observed_job: &JobObjectIdentity,
        observed_executable: &Path,
        observed_file: FileIdentity,
    ) -> Result<(), LaunchTupleError> {
        if observed_job != &self.inner_job {
            return Err(LaunchTupleError::IdentityMismatch);
        }
        if observed_executable != self.approved_executable.as_path() {
            return Err(LaunchTupleError::IdentityMismatch);
        }
        if observed_file.volume_serial_number == 0 || observed_file.file_index == 0 {
            // A zero file identity is "no image was observed", never "the image
            // matches"; projecting it as agreement would weaken the
            // approved-executable element.
            return Err(LaunchTupleError::Unavailable);
        }
        if let Some(outer) = &self.outer_binding
            && !is_kernel_outer_job_name(outer.job_identity().name())
        {
            return Err(LaunchTupleError::IdentityMismatch);
        }
        Ok(())
    }

    /// Element 1: the operation/attempt this launch is one attempt of.
    #[must_use]
    pub const fn operation_id(&self) -> &eliot_process::OperationId {
        &self.operation_id
    }

    /// Element 2: the owner generation whose manifest admitted these limits.
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Element 3a: the approved executable for this launch.
    #[must_use]
    pub fn approved_executable(&self) -> &Path {
        &self.approved_executable
    }

    /// Element 3b: the admitted `executable_sha256` this launch was sealed
    /// against.
    #[must_use]
    pub fn approved_executable_sha256(&self) -> &str {
        &self.approved_executable_sha256
    }

    /// Element 4: the declared execution identity.
    ///
    /// GAP (reported, not faked): `ExecutionIdentityMode` has no admitted
    /// producer reachable from this crate. `SuspendedLaunchSpec::new`
    /// hard-codes `UserMode` and `SuspendedLaunchSpec::with_execution_identity`
    /// has no call site anywhere in the tree, so every launch today silently
    /// declares `UserMode`. The platform layer's
    /// `select_execution_identity_mode` / `selected_execution_identity_sid`
    /// (W4, `process_identity.rs`) are the lawful producers but are themselves
    /// uncalled, and neither the Module Manifest nor `ProcessRequest` carries a
    /// per-launch identity name. This crate therefore binds the element from
    /// the one lawful source it can reach -- the identity the launch spec
    /// declares -- rather than inventing one. See the delivery report for the
    /// exact missing caller and its file.
    #[must_use]
    pub const fn execution_identity(&self) -> ExecutionIdentityMode {
        self.execution_identity
    }

    /// Element 5: the admitted Module Manifest Job ceilings.
    #[must_use]
    pub const fn manifest_limits(&self) -> JobObjectLimits {
        self.manifest_limits
    }

    /// Element 6a: the exact Host-owned outer Job binding, when this launch has
    /// one.
    ///
    /// `None` is the `#[cfg(test)]` launch seam, which creates the per-attempt
    /// Job with no Host-owned outer Job; see the field docs. A production
    /// launch always yields `Some`.
    #[must_use]
    pub fn outer_binding(&self) -> Option<&RecoverableJobBinding> {
        self.outer_binding.as_ref()
    }

    /// Element 6b: the exact per-attempt inner Job identity.
    #[must_use]
    pub const fn inner_job(&self) -> &JobObjectIdentity {
        &self.inner_job
    }
}

/// Whether `job_name` is the Host-owned Kernel outer kill domain Job Object.
///
/// `I1.6` requires that "Kernel descendants remain inside the Host-owned
/// Kernel Job Object", so the outer element of a bound tuple may only name that
/// domain's Job Object. A per-attempt nested name is not one: nesting never
/// mints a second outer kill domain, so `Local\\Eliot-P04-...` is refused here.
///
/// Split out from [`ValidatedLaunchTuple::bind`] so the refusal rule is provable
/// from a Job name alone, which is all this predicate reads; `bind` remains the
/// only production caller that turns the answer into a launch refusal.
#[cfg(windows)]
fn is_kernel_outer_job_name(job_name: &str) -> bool {
    OuterKillDomain::Kernel.owns_host_job_name(job_name)
}

/// Why a launch tuple is refused.
///
/// Kept typed so the executor maps a pre-effect refusal onto its own typed
/// `ProcessExecutionError::Unavailable` without collapsing the reason, and
/// without turning a pre-resume refusal into a possible-effect outcome.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchTupleError {
    /// An element the tuple cannot omit is absent (blank executable or digest).
    Missing,
    /// The live observation disagrees with a bound element, or the bound outer
    /// binding is not this exact Host-owned Kernel outer Job.
    IdentityMismatch,
    /// The live observation could not be read, so agreement cannot be shown.
    Unavailable,
}

#[cfg(windows)]
impl std::fmt::Display for LaunchTupleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => f.write_str("launch tuple element is absent"),
            Self::IdentityMismatch => {
                f.write_str("launch tuple disagrees with the live suspended-child observation")
            }
            Self::Unavailable => f.write_str("live suspended-child observation could not be read"),
        }
    }
}

#[cfg(windows)]
impl std::error::Error for LaunchTupleError {}

#[cfg(all(test, windows))]
mod tests {
    use super::{LaunchTupleError, ValidatedLaunchTuple, is_kernel_outer_job_name};
    use eliot_platform_windows::{
        ExecutionIdentityMode, FileIdentity, JobObjectIdentity, JobObjectLimits,
    };
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, EnvironmentProjection,
        FencingToken, Generation, ImageId, JobId, KernelDispatchKey, OperationId, PermitIssuance,
        ProcessIntent, ProcessRequest, ProcessTreeId, ResourceLimits, SessionId,
    };
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    fn test_epoch(sequence: u64) -> eliot_contracts::EpochId {
        use eliot_contracts::{EpochId, EpochLineageId};
        use std::num::NonZeroU64;
        let lineage =
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("canonical lineage");
        EpochId::new(
            lineage,
            NonZeroU64::new(sequence).expect("non-zero sequence"),
        )
        .expect("valid test epoch")
    }

    fn revisions() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("authority".to_owned(), "a".repeat(64)),
            ("state".to_owned(), "b".repeat(64)),
        ])
    }

    /// One fully admitted `ProcessRequest`, built through the same authority
    /// path every other proof in this crate uses.
    fn admitted_request(
        executable: &str,
        digest: &str,
    ) -> Result<(ProcessRequest, DispatchPermitAuthority), Box<dyn std::error::Error>> {
        let operation_id = OperationId::new("op-aud3-tuple")?;
        let generation = Generation::new(3)?;
        let intent = ProcessIntent::new(
            operation_id,
            ProcessTreeId::new("tree-aud3-tuple")?,
            JobId::new("job-aud3-tuple")?,
            ImageId::new("image-aud3-tuple")?,
            SessionId::new("session-aud3-tuple")?,
            generation,
            executable,
            digest,
            vec!["/c".to_owned(), "echo".to_owned(), "hi".to_owned()],
            std::env::temp_dir().to_string_lossy().into_owned(),
            EnvironmentProjection::default(),
            ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?,
        )?;
        let fence = FencingToken::new(test_epoch(1), generation, "fence-aud3-tuple")?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("auth-aud3-tuple")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new("lease-aud3-tuple")?,
                fence,
                revisions(),
                100,
                10_000,
                "nonce-aud3-tuple",
            )?,
        )?;
        Ok((ProcessRequest::new(intent, permit)?, authority))
    }

    const EXECUTABLE: &str = r"C:\Windows\System32\cmd.exe";
    const DIGEST_PLACEHOLDER: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    fn inner_job(name: &str) -> JobObjectIdentity {
        JobObjectIdentity::new(name).expect("valid inner Job name")
    }

    fn observed_file() -> FileIdentity {
        FileIdentity {
            volume_serial_number: 7,
            file_index: 42,
        }
    }

    /// POSITIVE: a tuple bound to every element is accepted by the pre-resume
    /// re-check when the live observation is that same child and Job.
    #[test]
    fn bound_tuple_accepts_the_matching_live_observation() -> Result<(), Box<dyn std::error::Error>>
    {
        let (request, _authority) = admitted_request(EXECUTABLE, DIGEST_PLACEHOLDER)?;
        let job = inner_job("Local\\Eliot-P04-1-1");
        let tuple = ValidatedLaunchTuple::bind_without_outer_job(
            &request,
            Path::new(EXECUTABLE),
            DIGEST_PLACEHOLDER,
            ExecutionIdentityMode::UserMode,
            JobObjectLimits::default(),
            job.clone(),
        )?;
        assert_eq!(tuple.operation_id().as_str(), "op-aud3-tuple");
        assert_eq!(tuple.generation(), Generation::new(3)?);
        assert_eq!(tuple.approved_executable(), PathBuf::from(EXECUTABLE));
        assert_eq!(tuple.approved_executable_sha256(), DIGEST_PLACEHOLDER);
        assert_eq!(tuple.execution_identity(), ExecutionIdentityMode::UserMode);
        assert_eq!(tuple.manifest_limits(), JobObjectLimits::default());
        assert!(tuple.outer_binding().is_none());
        assert_eq!(tuple.inner_job(), &job);
        tuple.compare_observed(&job, Path::new(EXECUTABLE), observed_file())?;
        Ok(())
    }

    /// REFUSAL: the child the platform reports is in a different Job Object
    /// than the one this tuple bound. A non-null Job name on either side is
    /// not enough; the identities must be the same Job.
    #[test]
    fn bound_tuple_refuses_a_child_in_another_job() -> Result<(), Box<dyn std::error::Error>> {
        let (request, _authority) = admitted_request(EXECUTABLE, DIGEST_PLACEHOLDER)?;
        let tuple = ValidatedLaunchTuple::bind_without_outer_job(
            &request,
            Path::new(EXECUTABLE),
            DIGEST_PLACEHOLDER,
            ExecutionIdentityMode::UserMode,
            JobObjectLimits::default(),
            inner_job("Local\\Eliot-P04-1-1"),
        )?;
        let error = tuple
            .compare_observed(
                &inner_job("Local\\Eliot-P04-1-2"),
                Path::new(EXECUTABLE),
                observed_file(),
            )
            .expect_err("a child in another Job must be refused before resume");
        assert_eq!(error, LaunchTupleError::IdentityMismatch);
        Ok(())
    }

    /// REFUSAL: the child the platform reports was created from a different
    /// executable than the one the tuple approved.
    #[test]
    fn bound_tuple_refuses_an_unapproved_executable() -> Result<(), Box<dyn std::error::Error>> {
        let (request, _authority) = admitted_request(EXECUTABLE, DIGEST_PLACEHOLDER)?;
        let job = inner_job("Local\\Eliot-P04-1-1");
        let tuple = ValidatedLaunchTuple::bind_without_outer_job(
            &request,
            Path::new(EXECUTABLE),
            DIGEST_PLACEHOLDER,
            ExecutionIdentityMode::UserMode,
            JobObjectLimits::default(),
            job.clone(),
        )?;
        let error = tuple
            .compare_observed(
                &job,
                Path::new(r"C:\Windows\System32\whoami.exe"),
                observed_file(),
            )
            .expect_err("an unapproved image must be refused before resume");
        assert_eq!(error, LaunchTupleError::IdentityMismatch);
        Ok(())
    }

    /// REFUSAL: no image file identity was observed. Agreement must not be
    /// projected from an absent reading.
    #[test]
    fn bound_tuple_refuses_an_absent_observed_image() -> Result<(), Box<dyn std::error::Error>> {
        let (request, _authority) = admitted_request(EXECUTABLE, DIGEST_PLACEHOLDER)?;
        let job = inner_job("Local\\Eliot-P04-1-1");
        let tuple = ValidatedLaunchTuple::bind_without_outer_job(
            &request,
            Path::new(EXECUTABLE),
            DIGEST_PLACEHOLDER,
            ExecutionIdentityMode::UserMode,
            JobObjectLimits::default(),
            job.clone(),
        )?;
        let error = tuple
            .compare_observed(
                &job,
                Path::new(EXECUTABLE),
                FileIdentity {
                    volume_serial_number: 0,
                    file_index: 0,
                },
            )
            .expect_err("an absent observed image must not be read as agreement");
        assert_eq!(error, LaunchTupleError::Unavailable);
        Ok(())
    }

    /// POSITIVE: the exact Host-owned Kernel outer kill domain Job Object name
    /// is recognised, so [`ValidatedLaunchTuple::bind`] admits that outer
    /// element and the launch proceeds to the nested spawn.
    #[test]
    fn is_kernel_outer_job_name_accepts_the_kernel_outer_kill_domain() {
        assert!(is_kernel_outer_job_name("Local\\Eliot-Host-Kernel-1a2b3c"));
    }

    /// REFUSAL: only that one domain's Job Object is an outer element.
    ///
    /// Each name below is a Job Object this launch must NOT treat as the
    /// Host-owned Kernel outer kill domain, so `bind` refuses it before any
    /// child exists: a per-attempt nested name (nesting never mints a second
    /// outer domain), the Store domain, the independent Watchdog domain
    /// (`AUD2`: a Kernel launch is never adopted into the Watchdog kill tree),
    /// and the bare domain prefix with an empty suffix, which names no Job.
    #[test]
    fn is_kernel_outer_job_name_refuses_every_non_kernel_outer_name() {
        assert!(!is_kernel_outer_job_name("Local\\Eliot-P04-1234-7"));
        assert!(!is_kernel_outer_job_name("Local\\Eliot-Host-Store-1a2b3c"));
        assert!(!is_kernel_outer_job_name(
            "Local\\Eliot-Host-Watchdog-1a2b3c"
        ));
        assert!(!is_kernel_outer_job_name("Local\\Eliot-Host-Kernel-"));
    }

    /// REFUSAL: an element the tuple cannot omit is absent.
    #[test]
    fn bind_refuses_a_blank_approved_executable() -> Result<(), Box<dyn std::error::Error>> {
        let (request, _authority) = admitted_request(EXECUTABLE, DIGEST_PLACEHOLDER)?;
        let error = ValidatedLaunchTuple::bind_without_outer_job(
            &request,
            Path::new(""),
            DIGEST_PLACEHOLDER,
            ExecutionIdentityMode::UserMode,
            JobObjectLimits::default(),
            inner_job("Local\\Eliot-P04-1-1"),
        )
        .expect_err("a blank executable is not an approved element");
        assert_eq!(error, LaunchTupleError::Missing);
        Ok(())
    }
}
