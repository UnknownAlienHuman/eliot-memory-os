//! I14.16 exclusive-Kernel-ownership evidence for the Host-mediated
//! side-by-side cutover.
//!
//! Host owns the decision, not the object. The exclusive Kernel owner object
//! is created by exactly one Kernel process (see
//! `eliot_platform_windows::KernelOwnerLease`); this module only observes it.
//! Two observations are possible and they are opposite:
//!
//! * a *retired* contour is proven released only when Host itself can create
//!   that contour's object - that is, when the retired process already closed
//!   it. A live object, an unclassifiable Win32 result, or a platform without
//!   the primitive is never a release, and the cutover stops;
//! * a *candidate* contour is proven held only when Host cannot create that
//!   contour's object. If Host can create it, the candidate never took
//!   exclusive ownership and must not be marked active.
//!
//! Neither observation is a shape or name check: both are attempts to create
//! the same operating-system object the Kernel itself had to create.

use eliot_host_state::{KernelRecord, PriorKernelDisposition, PriorKernelSource};
use eliot_platform_windows::{KernelOwnerLease, KernelOwnerLeaseError, kernel_owner_mutex_name};

use super::{HostError, HostKernelCandidateBinding, PlatformHandle};

/// The retained I14.16 step-5 handoff boundary for one retired Kernel.
///
/// Every field is a Host observation of the retired contour - the exact Job
/// root that owned authority, the exact process identity that Job reported,
/// the exact generation it was admitted under, and the exclusive owner object
/// that contour had to release. The receipt asserts nothing by itself: it is
/// accepted only by comparing it against the prior disposition this very
/// activation already recorded, and it authorizes nothing until
/// [`Self::prove_released`] succeeds on the live object.
#[derive(Clone)]
pub(super) struct KernelHandoffReceipt {
    prior: PriorKernelSource,
    owner_object: String,
}

impl KernelHandoffReceipt {
    /// Builds the receipt for the disposition Host just proved for this
    /// activation, or `None` when there was no prior Kernel at all.
    ///
    /// A running or unobserved prior contour produces an error instead: Host
    /// may not write a handoff receipt for a Kernel it has not terminated.
    pub(super) fn for_disposition(
        disposition: &PriorKernelDisposition,
    ) -> Result<Option<Self>, HostError> {
        match disposition {
            PriorKernelDisposition::NoPriorKernel => Ok(None),
            PriorKernelDisposition::Terminated(prior) => Ok(Some(Self {
                owner_object: kernel_owner_mutex_name(
                    &prior.host.installation,
                    &prior.activation_identity,
                ),
                prior: prior.clone(),
            })),
            PriorKernelDisposition::Running(_) | PriorKernelDisposition::Unknown(_) => {
                Err(HostError::RecoveryRequired(
                    "Kernel handoff receipt requires an exactly terminated prior contour"
                        .to_owned(),
                ))
            }
        }
    }

    /// Compares this receipt with the prior disposition the activation already
    /// carries, so a receipt for a different retired contour cannot advance
    /// this one.
    pub(super) fn matches_disposition(&self, disposition: &PriorKernelDisposition) -> bool {
        matches!(disposition, PriorKernelDisposition::Terminated(prior) if *prior == self.prior)
    }

    /// Recovers the handoff boundary this activation already retained in its
    /// durable `KernelRecord`, after a restart dropped the in-memory copy.
    ///
    /// I14.16 step 6 (issue #1953, map item 3): the candidate manifest/pipe,
    /// the old-Kernel handoff, the exact old PID/start/Job identity, the
    /// observed termination flags and the owner-lock acquisition target join
    /// ONE retained activation record. `resume()` restores only that record,
    /// so without this the retained `HandoffPrepared` boundary would be
    /// unreachable and the commit could never run under the original Host
    /// activation. Recovery rebuilds the receipt from the record's own prior
    /// disposition and admits it only when the record's
    /// `disposition_evidence` already carries this exact receipt's evidence
    /// reference - the durable proof that this activation prepared this
    /// handoff. A `Running`/`Unknown` disposition, or a terminated contour
    /// with no retained handoff evidence, stops activation with
    /// `RecoveryRequired`; the journal record itself is untouched and stays
    /// queryable.
    pub(super) fn recover_retained(current: &KernelRecord) -> Result<Option<Self>, HostError> {
        let Some(receipt) = Self::for_disposition(&current.prior_kernel_disposition)? else {
            return Ok(None);
        };
        let evidence = receipt.evidence_ref()?;
        if !current.disposition_evidence.contains(&evidence) {
            return Err(HostError::RecoveryRequired(
                "retained Kernel record carries no prepared handoff boundary for its prior contour"
                    .to_owned(),
            ));
        }
        Ok(Some(receipt))
    }

    /// Proves the retired contour actually released its exclusive owner
    /// object, by creating that exact object itself.
    ///
    /// Creating the object is the only available proof: a name, a PID, a Job
    /// observation, or a timeout cannot show that no other process still owns
    /// it. Host releases the probe object immediately so the replacement
    /// contour can take its own.
    pub(super) fn prove_released(&self) -> Result<(), HostError> {
        let mut probe = KernelOwnerLease::acquire_named(&self.owner_object).map_err(|error| {
            HostError::RecoveryRequired(format!(
                "retired Kernel owner object could not be classified as released ({error})"
            ))
        })?;
        probe.release().map_err(|error| {
            HostError::RecoveryRequired(format!(
                "retired Kernel owner object probe could not be released ({error})"
            ))
        })
    }

    /// The retained evidence reference for the durable handoff transition.
    pub(super) fn evidence_ref(&self) -> Result<PlatformHandle, HostError> {
        PlatformHandle::new(format!("kernel-handoff-receipt:{}", self.owner_object))
            .map_err(|error| HostError::Platform(error.to_string()))
    }
}

/// Proves the candidate Kernel holds exclusive ownership of its own contour.
///
/// Host must not be able to create the candidate's owner object. If it can,
/// the candidate never took exclusive ownership, and the activation is
/// refused before the stable front door is published - never after.
pub(super) fn prove_candidate_owner_held(
    candidate: &HostKernelCandidateBinding,
) -> Result<(), HostError> {
    let name = kernel_owner_mutex_name(&candidate.installation_id, &candidate.activation_id);
    match KernelOwnerLease::acquire_named(&name) {
        Err(KernelOwnerLeaseError::ExistingObject) => Ok(()),
        Ok(mut unclaimed) => {
            // The candidate's object was free, so nothing holds exclusive
            // ownership of that contour. Release the probe before refusing so
            // the refusal is not itself the reason a retry fails.
            let _ = unclaimed.release();
            Err(HostError::ProcessContour(
                "candidate Kernel does not hold its exclusive owner object".to_owned(),
            ))
        }
        Err(error) => Err(HostError::RecoveryRequired(format!(
            "candidate Kernel owner object could not be classified ({error})"
        ))),
    }
}
