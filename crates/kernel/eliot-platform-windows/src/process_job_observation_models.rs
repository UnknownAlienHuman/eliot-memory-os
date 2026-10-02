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
use super::JobLaunchContainment;
#[cfg(windows)]
use super::JobObjectIdentity;
#[cfg(windows)]
use super::OuterKillDomain;

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

    /// Reports whether this observation and `other` are the SAME live child.
    ///
    /// Audit comment `5871793301` item 5 requires that "A successful unrelated
    /// probe does not attest this child", so an observation is usable for a
    /// launch only when it carries that launch's own retained-handle identity.
    /// Two launches differ in the process identity observed through their own
    /// handles, so this element-wise comparison is what binds an observation
    /// to one child. It compares identities; it never reports that some
    /// observation exists.
    #[must_use]
    pub fn is_same_child(&self, other: &Self) -> bool {
        self.process == other.process && self.executable == other.executable
    }

    /// Requires that this observation was taken for the same live child as
    /// `expected`.
    ///
    /// # Errors
    /// Returns [`WindowsAdapterError::IdentityMismatch`] when the two
    /// observations are of different children. That refusal is scoped to THIS
    /// launch's evidence: it never withdraws the other launch's own
    /// observation, and it never terminates a process.
    pub fn require_same_child(&self, expected: &Self) -> Result<(), WindowsAdapterError> {
        if self.is_same_child(expected) {
            Ok(())
        } else {
            Err(WindowsAdapterError::IdentityMismatch)
        }
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

/// Why one launch's containment evidence could not be established.
///
/// `I1.6` requires that "startup probes verify the required nesting and
/// kill-on-close semantics on the supported Windows build", and audit comment
/// `5871793301` item 5 states that "Missing evidence keeps only the affected
/// launch unavailable and must not terminate or block the independent
/// Watchdog/control path".
///
/// This is a degradation, not a process outcome: no variant terminates a
/// process, closes a Job Object, or reports a fault that any sibling launch, the
/// Host, or the Watchdog branch can observe. The typed projection exists so a
/// caller cannot invent a second, wider consequence for the same missing
/// evidence.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchEvidenceUnavailable {
    /// This Windows build has no observed nesting/kill-on-close verdict for the
    /// kill domain this launch must use. That verdict is per kill domain, not a
    /// claim about any individual child, so this degrades only the launches
    /// that require this domain and leaves every other launch's own evidence
    /// untouched.
    BuildSupportNotEstablished {
        /// The outer kill domain whose nesting semantics are unestablished.
        domain: OuterKillDomain,
    },
    /// The exact outer Job this launch must nest inside could not be read back
    /// from the kernel, so its kill-on-close flag and ceilings are unknown for
    /// THIS launch only. A sibling launch holding a different outer Job keeps
    /// its own separate read-back.
    OuterJobNotReobserved,
    /// The child this launch created could not be observed as a member of the
    /// exact outer Job it must stay inside. Only THIS launch is refused; the
    /// children of other launches are decided by their own Jobs.
    ChildNotObservedInOuterJob,
}

#[cfg(windows)]
impl LaunchEvidenceUnavailable {
    /// Projects this degradation onto the typed adapter error the launch API
    /// returns, without erasing which evidence was missing.
    ///
    /// A build that cannot establish the required nesting and kill-on-close is
    /// `Unavailable`; evidence that exists but disagrees with THIS launch's
    /// identity is `IdentityMismatch`. The mapping is total and one-way: a
    /// caller receives a typed error, never a boolean that could later be
    /// reused as a weaker global verdict.
    #[must_use]
    pub const fn to_adapter_error(self) -> WindowsAdapterError {
        match self {
            Self::BuildSupportNotEstablished { .. } => WindowsAdapterError::Unavailable,
            Self::OuterJobNotReobserved | Self::ChildNotObservedInOuterJob => {
                WindowsAdapterError::IdentityMismatch
            }
        }
    }
}

/// The one observed fact that this Windows build supports the nesting and
/// kill-on-close semantics a launch relies on.
///
/// `I1.6` requires that "startup probes verify the required nesting and
/// kill-on-close semantics on the supported Windows build". This adds NO second
/// probe: it is the already-observed [`JobLaunchContainment`] verdict
/// re-projected with its two observed facts still attached, and the only
/// constructor takes that verdict. There is no path that yields this type from
/// a constant, a permissive default, or another domain's success, so it cannot
/// stand in for a probe that never ran.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildNestingSupport {
    /// The kill domain the real probe observed assignment, permitted nesting,
    /// and outer kill-on-close for.
    domain: OuterKillDomain,
    /// The different kill domain the probe observed still running after
    /// `domain`'s outer Job Object was closed.
    contrasted_domain: OuterKillDomain,
}

#[cfg(windows)]
impl BuildNestingSupport {
    /// Re-projects one real experiment verdict as this build's support fact.
    ///
    /// The caller is the platform owner that already ran or retrieved the
    /// cached verdict behind [`super::probe_launch_containment`]; this
    /// performs no observation of its own, so it cannot invent support where the
    /// probe failed.
    #[must_use]
    pub const fn from_observed_verdict(verdict: JobLaunchContainment) -> Self {
        Self {
            domain: verdict.domain(),
            contrasted_domain: verdict.distinct_domain(),
        }
    }

    /// Returns the kill domain this build's nesting and kill-on-close
    /// semantics were observed for.
    #[must_use]
    pub const fn domain(self) -> OuterKillDomain {
        self.domain
    }

    /// Returns the different kill domain this verdict was contrasted against,
    /// which is what shows the two domains do not share a kill domain.
    #[must_use]
    pub const fn contrasted_domain(self) -> OuterKillDomain {
        self.contrasted_domain
    }

    /// Requires that this build's observed support covers `required`.
    ///
    /// This compares the observed identity of the verdict; it never reports
    /// that some verdict merely exists. A verdict observed for another domain,
    /// or one not contrasted against a different domain, is not support for the
    /// domain this launch must use.
    ///
    /// # Errors
    /// Returns [`LaunchEvidenceUnavailable::BuildSupportNotEstablished`] when
    /// the observed verdict does not cover `required`.
    pub const fn require_support_for(
        self,
        required: OuterKillDomain,
    ) -> Result<(), LaunchEvidenceUnavailable> {
        // `same_domain` rather than `==` / `!=`: this is a `const fn` and the
        // derived `PartialEq` operator is not const-callable. BOTH conditions
        // are checked, exactly as before: the verdict's own domain must be
        // `required`, AND it must have been contrasted against a DIFFERENT
        // domain, which is what shows the two do not share a kill domain. A
        // verdict that was never contrasted establishes nothing and is refused.
        if same_domain(self.domain, required) && !same_domain(self.contrasted_domain, required) {
            Ok(())
        } else {
            Err(LaunchEvidenceUnavailable::BuildSupportNotEstablished { domain: required })
        }
    }
}

/// Returns whether two `OuterKillDomain` values are the SAME domain, in a
/// `const` context.
///
/// `OuterKillDomain`'s derived `PartialEq` operator is not `const`-callable, so a
/// `const fn` cannot use `==`. `OuterKillDomain` has exactly three unit variants
/// and no payload, so each side is decided by its own variant and the two
/// verdicts are combined: same variant on BOTH sides is the SAME domain, and any
/// other combination is a DIFFERENT domain. Every one of the nine combinations
/// is decided, with no normalisation and no wildcard arm.
const fn same_domain(left: OuterKillDomain, right: OuterKillDomain) -> bool {
    let left_is_kernel = matches!(left, OuterKillDomain::Kernel);
    let left_is_store = matches!(left, OuterKillDomain::Store);
    let left_is_watchdog = matches!(left, OuterKillDomain::Watchdog);
    let right_is_kernel = matches!(right, OuterKillDomain::Kernel);
    let right_is_store = matches!(right, OuterKillDomain::Store);
    let right_is_watchdog = matches!(right, OuterKillDomain::Watchdog);
    (left_is_kernel && right_is_kernel)
        || (left_is_store && right_is_store)
        || (left_is_watchdog && right_is_watchdog)
}

/// One launch's bounded, typed containment evidence: the three observed facts
/// comment `5871793301` item 5 asks for, bound to THIS child and THESE Jobs.
///
/// 1. This build supports the nesting and kill-on-close semantics in use,
///    carried as [`Self::build_support`] and derived only from the real
///    experiment behind [`BuildNestingSupport`].
/// 2. The evidence is bound to this child and these Jobs, carried as
///    [`Self::child`] and enforced by [`Self::require_same_outer_job`], so an
///    unrelated launch's success cannot attest this child.
/// 3. What happens when it is unavailable, carried as
///    [`LaunchEvidenceUnavailable`].
///
/// This is deliberately not a boolean. [`Self::require_same_outer_job`]
/// compares the evidence's own observed identity against the launch presenting
/// it, and the refusal names exactly which evidence was missing, so a caller
/// cannot widen the consequence past this one launch.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchContainmentEvidence {
    support: BuildNestingSupport,
    child: ProcessObservation,
    outer_job: JobObjectIdentity,
}

#[cfg(windows)]
impl LaunchContainmentEvidence {
    /// Joins this build's observed support with the exact child and outer Job
    /// this launch was observed against.
    ///
    /// # Errors
    /// Returns [`LaunchEvidenceUnavailable::BuildSupportNotEstablished`] when
    /// the observed verdict does not cover the kill domain `outer_job` belongs
    /// to. That refusal reports the missing capability for this launch's
    /// domain; it is never a verdict about another launch's child.
    pub fn observe(
        verdict: JobLaunchContainment,
        outer_job: JobObjectIdentity,
        child: ProcessObservation,
    ) -> Result<Self, LaunchEvidenceUnavailable> {
        let support = BuildNestingSupport::from_observed_verdict(verdict);
        let required = super::outer_kill_domain_of_job_name(outer_job.name())
            .ok_or(LaunchEvidenceUnavailable::OuterJobNotReobserved)?;
        support.require_support_for(required)?;
        Ok(Self {
            support,
            child,
            outer_job,
        })
    }

    /// Returns this build's observed nesting and kill-on-close support fact.
    #[must_use]
    pub const fn build_support(&self) -> BuildNestingSupport {
        self.support
    }

    /// Requires that this evidence was observed for exactly this launch: the
    /// same child and the same outer Job Object the caller is about to permit.
    ///
    /// This is the clause that unrelated success cannot attest this child. The
    /// caller compares the evidence's own observed identity against the live
    /// launch rather than checking that some evidence exists, so another
    /// launch's genuine observation is refused here instead of borrowed.
    ///
    /// # Errors
    /// Returns [`LaunchEvidenceUnavailable::ChildNotObservedInOuterJob`] when
    /// the child or the outer Job differs, and
    /// [`LaunchEvidenceUnavailable::OuterJobNotReobserved`] when `outer_job`
    /// names no Host-owned outer kill domain at all. Each refusal is scoped to
    /// this one launch and withdraws nothing from the other launch.
    pub fn require_same_outer_job(
        &self,
        child: &ProcessObservation,
        outer_job: &JobObjectIdentity,
    ) -> Result<(), LaunchEvidenceUnavailable> {
        if self.child != *child || self.outer_job != *outer_job {
            return Err(LaunchEvidenceUnavailable::ChildNotObservedInOuterJob);
        }
        if super::outer_kill_domain_of_job_name(outer_job.name()).is_none() {
            return Err(LaunchEvidenceUnavailable::OuterJobNotReobserved);
        }
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod launch_containment_evidence_tests {
    use super::{
        BuildNestingSupport, LaunchContainmentEvidence, LaunchEvidenceUnavailable,
        ProcessObservation,
    };
    use crate::process_job::{JobLaunchContainment, JobObjectIdentity, OuterKillDomain};
    use crate::{FileIdentity, ProcessIdentity};

    fn outer(domain: OuterKillDomain) -> JobObjectIdentity {
        JobObjectIdentity {
            name: format!("{}epoch-7", domain.host_job_name_prefix()),
        }
    }

    fn observed_child(process_id: u32) -> ProcessObservation {
        ProcessObservation {
            process: ProcessIdentity {
                process_id,
                start_time_100ns: 1_337,
                image_path: "C:\\Program Files\\Eliot\\module.exe".to_string(),
            },
            executable: FileIdentity {
                volume_serial_number: 0x00A1,
                file_index: 4_242,
            },
        }
    }

    /// A verdict only the real experiment can mint, built from the same private
    /// fields the observation path populates.
    fn verdict(domain: OuterKillDomain) -> JobLaunchContainment {
        JobLaunchContainment {
            domain,
            distinct_domain: domain.contrasting_domain(),
        }
    }

    // POSITIVE: a Kernel verdict bound to THIS child and THIS outer Job attests
    // this launch, and support compares by observed identity.
    #[test]
    fn same_child_and_outer_job_attest_this_launch() {
        let kernel_outer_job = outer(OuterKillDomain::Kernel);
        let child = observed_child(4_242);
        let observed = LaunchContainmentEvidence::observe(
            verdict(OuterKillDomain::Kernel),
            kernel_outer_job.clone(),
            child.clone(),
        );
        let Ok(evidence) = observed else {
            panic!("Kernel verdict must cover the Kernel outer Job");
        };
        assert_eq!(evidence.build_support().domain(), OuterKillDomain::Kernel);
        assert_eq!(
            evidence.build_support().contrasted_domain(),
            OuterKillDomain::Watchdog
        );
        assert_eq!(
            BuildNestingSupport::from_observed_verdict(verdict(OuterKillDomain::Kernel))
                .require_support_for(OuterKillDomain::Kernel),
            Ok(())
        );
        assert_eq!(
            evidence.require_same_outer_job(&child, &kernel_outer_job),
            Ok(())
        );
    }

    // REFUSAL: an unrelated launch's evidence -- a different child observed
    // against the same outer Job -- must not attest this child, and the
    // degradation stays typed and one launch wide.
    #[test]
    fn unrelated_child_evidence_is_refused() {
        let kernel_outer_job = outer(OuterKillDomain::Kernel);
        let observed = LaunchContainmentEvidence::observe(
            verdict(OuterKillDomain::Kernel),
            kernel_outer_job.clone(),
            observed_child(9_001),
        );
        let Ok(evidence) = observed else {
            panic!("Kernel verdict must cover the Kernel outer Job");
        };
        // This launch's child was never the observed child: refused, and typed.
        assert_eq!(
            evidence.require_same_outer_job(&observed_child(4_242), &kernel_outer_job),
            Err(LaunchEvidenceUnavailable::ChildNotObservedInOuterJob)
        );
        assert_eq!(
            LaunchEvidenceUnavailable::ChildNotObservedInOuterJob.to_adapter_error(),
            crate::WindowsAdapterError::IdentityMismatch
        );
        assert_eq!(
            LaunchEvidenceUnavailable::BuildSupportNotEstablished {
                domain: OuterKillDomain::Kernel,
            }
            .to_adapter_error(),
            crate::WindowsAdapterError::Unavailable
        );
    }

    // REFUSAL: a verdict observed for another kill domain and a nested
    // per-attempt name are both refused, while the Watchdog branch's own launch
    // keeps its own separate evidence.
    #[test]
    fn unrelated_domain_verdict_and_nested_name_are_refused() {
        // A Watchdog verdict observed against the Kernel outer Job: refused.
        assert_eq!(
            LaunchContainmentEvidence::observe(
                verdict(OuterKillDomain::Watchdog),
                outer(OuterKillDomain::Kernel),
                observed_child(4_242),
            )
            .err(),
            Some(LaunchEvidenceUnavailable::BuildSupportNotEstablished {
                domain: OuterKillDomain::Kernel,
            })
        );
        // A per-attempt nested name is not an outer kill domain at all.
        assert_eq!(
            LaunchContainmentEvidence::observe(
                verdict(OuterKillDomain::Kernel),
                JobObjectIdentity {
                    name: "Local\\Eliot-P02-77-1".to_string(),
                },
                observed_child(4_242),
            )
            .err(),
            Some(LaunchEvidenceUnavailable::OuterJobNotReobserved)
        );
        // The Watchdog branch's own launch is unaffected by either refusal.
        assert!(
            LaunchContainmentEvidence::observe(
                verdict(OuterKillDomain::Watchdog),
                outer(OuterKillDomain::Watchdog),
                observed_child(9_001),
            )
            .is_ok()
        );
    }
}
