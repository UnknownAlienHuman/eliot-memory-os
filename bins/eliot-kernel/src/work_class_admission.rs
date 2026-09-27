//! Kernel-owned I14.1 admission boundary (issue #1920).
//!
//! The pool semantics themselves — one bounded pool per I14.1 work class, the
//! reserved control partition, the declared items/bytes/concurrency/deadline
//! bounds, the documented shedding order, and the admitted work record with its
//! retry budget and cancellation state — are owned by
//! [`eliot_kernel_core::module::work_class_admission`]. This module is the
//! owner-local composition boundary for issue #1920: it makes that API
//! reachable from the Kernel submission path, keeps the single installed
//! scheduler handle on the composition, and records the overload disposition
//! through the single Kernel audit chain so an audit-critical event stays
//! recorded while lower-priority work is shed.
//!
//! Nothing here is a second scheduler, a second queue, or a second audit writer:
//! the composition holds exactly one [`WorkClassScheduler`] and appends through
//! the one [`crate::kernel_audit::KernelAuditChain`].

use std::sync::Mutex;

use eliot_kernel_core::{
    AdmittedWork, AdmissionClass, PoolAvailability, WorkAdmissionRefusal, WorkAdmissionRequest,
    WorkClassScheduler,
};

use crate::{
    KernelComposition, KernelConfig, kernel_audit::AuditEventDraft,
};

/// The composition's single I14.1 admission handle.
///
/// I14.1 names the work classes and I14.2 keeps the per-pool numbers in the
/// installed runtime profile, so the handle exists only when an operator
/// profile was injected. It is `Sync` and shared by every submission path, so
/// the pools are process-wide for this composition and no submission path can
/// obtain a private budget.
pub type KernelWorkClassAdmission = Mutex<WorkClassScheduler>;

impl KernelComposition {
    /// Returns the composition's I14.1 work-class admission handle.
    ///
    /// Returns `None` when no operator budget profile was injected. Callers
    /// must fail closed in that case: there is no Kernel default profile, so an
    /// absent profile is not an unbounded admission.
    #[must_use]
    pub fn work_class_admission(&self) -> Option<&KernelWorkClassAdmission> {
        self.work_class_admission.as_ref()
    }

    /// Admits one submitted work unit under its declared I14.1 work class,
    /// before any process or task spawn.
    ///
    /// This is the production pre-spawn admission point. A caller that receives
    /// an [`AdmittedWork`] handle may start execution through that handle only;
    /// a refusal returns the exact typed disposition carrying the exhausted
    /// bound, the I14.4 disposition, the I14.6 work outcome and the documented
    /// shedding order, and the unit is never spawned.
    ///
    /// The pools are independent, so a controlled `normal_background` or
    /// `model_jobs` backlog cannot consume the capacity a `control` or
    /// `interactive` unit draws from: the reserved control pool and the
    /// interactive pool stay available while the background pool refuses.
    /// Overload also appends the disposition to the single Kernel audit chain
    /// as an audit-critical event, so the record of what was shed survives the
    /// overload that produced it.
    pub fn admit_submitted_work(
        &self,
        class: AdmissionClass,
        request: &WorkAdmissionRequest,
    ) -> Result<AdmittedWork, WorkAdmissionRefusal> {
        let Some(scheduler) = self.work_class_admission() else {
            // No installed profile: the class is still named in the refusal, so
            // the caller never silently substitutes a less protected class.
            return Err(WorkAdmissionRefusal::ProfileAbsent);
        };
        let now_unix_ms = crate::unix_ms();
        let mut scheduler = scheduler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match scheduler.admit(class, request, now_unix_ms) {
            Ok(admitted) => Ok(admitted),
            Err(refusal) => {
                drop(scheduler);
                self.audit_observe(
                    AuditEventDraft::work_class_admission_refused(class, request, &refusal),
                );
                Err(refusal)
            }
        }
    }

    /// Returns the observed capacity of one work-class pool against its
    /// declared bounds.
    ///
    /// Returns `None` when no operator budget profile was injected, so an
    /// unconstructed scheduler can never report a fabricated capacity.
    #[must_use]
    pub fn work_class_pool_availability(
        &self,
        class: AdmissionClass,
    ) -> Option<PoolAvailability> {
        let scheduler = self.work_class_admission()?;
        let scheduler = scheduler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Some(scheduler.pool(class).availability())
    }

    /// Returns the documented I14.2 load-shedding order, least protected class
    /// first, from the installed profile.
    ///
    /// Returns `None` when no operator budget profile was injected.
    #[must_use]
    pub fn work_class_shedding_order(&self) -> Option<Vec<AdmissionClass>> {
        let scheduler = self.work_class_admission()?;
        let scheduler = scheduler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Some(scheduler.shedding_order())
    }
}

/// Constructs the composition's I14.1 admission handle from an injected
/// operator budget profile.
///
/// A profile with a zero bound in any dimension is refused at construction, so
/// no pool can ever be unbounded in items, bytes, concurrency or its deadline
/// profile. A missing profile yields `None`, which the admission entrypoint
/// turns into an explicit typed refusal.
pub(super) fn admission_from_config(
    config: &KernelConfig,
) -> Result<Option<KernelWorkClassAdmission>, String> {
    config
        .work_class_budgets
        .map(WorkClassScheduler::new)
        .transpose()
        .map(|scheduler| scheduler.map(Mutex::new))
        .map_err(|error| error.to_string())
}
