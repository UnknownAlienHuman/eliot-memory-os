//! I14.1 bounded work-class admission and pool isolation (issue #1920).
//!
//! This module owns the Kernel's owner-local scheduler controls for the nine
//! I14.1 work classes:
//!
//! - [`AdmissionClass`] represents all nine classes plus the separately named
//!   audit-critical lane. Admission happens **before** any process or task
//!   spawn, and a unit is associated with its class before it can occupy any
//!   capacity (I14.1, I18.46).
//! - [`WorkClassBudgets`] declares the four bounds I14.1 names for every class
//!   — items, bytes, concurrency and a deadline profile. I14.2 states the
//!   per-pool numbers are defaults in `runtime.toml`, not Architecture, so no
//!   bound is a Kernel or Architecture default here: every value arrives from
//!   the operator profile and an unbound profile fails closed.
//! - [`WorkClassScheduler`] owns one independent pool per class. The reserved
//!   `control` pool is disjoint from every normal pool, so normal workload can
//!   never consume the control reserve (I14.3), and a `normal_background` or
//!   `model_jobs` backlog can never consume the capacity a `control` or
//!   `interactive` unit draws from (I14.8, I18.46).
//! - [`SHEDDING_ORDER`] is the documented load-shedding order. It contains
//!   exactly the classes whose I14.2 pressure behaviour is "pause/drop
//!   rebuildable work", "checkpoint/deny", "stop admission/replan" and
//!   "regenerate later". `control`, `interactive`, `verification` and
//!   `canonical_write` are absent and are therefore never shed under pressure.
//! - [`AdmittedWork`] is the admitted work record: it carries the declared
//!   work class, the mailbox cost, the deadline profile, the retry budget and
//!   the cancellation state, and it is the only handle through which a unit may
//!   start execution (I14.6, I14.8, I18.46).
//!
//! The nine class names are carried by the frozen [`NormalWorkClass`]
//! vocabulary from `eliot-runtime-contracts` plus the reserved `control` class.
//! The canonical `WorkClass` spelling type in `eliot-agent-coordinator` is
//! deliberately not reused here: that crate sits outside the `eliot-agent-`
//! runtime-root boundary and already depends on this crate, so the frozen
//! runtime-contract vocabulary is the only reachable one. Every `NormalWorkClass`
//! variant is named explicitly in every match below, so a new I14.1 class fails
//! to compile here instead of sorting silently.
//!
//! Every refusal is a typed value carrying the exact frozen I14 denominator
//! row, the I14.4 disposition and the I14.6 work outcome. No refusal is
//! collapsed into a string or a generic code.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use eliot_runtime_contracts::{
    BackpressureDisposition, BottleneckAvailability, BottleneckCoverageState,
    BottleneckObservationV1, CapacityBottleneck, I14WorkOutcome, NormalWorkClass,
};

use crate::FRONT_DOOR_BOTTLENECK;
use crate::error::{KernelError, validate_id};

/// The documented I14.2/I14.8 load-shedding order, least protected class first.
///
/// The order is the I14.1 document order reversed for shedding, so the class
/// whose pressure behaviour is most rebuildable is shed first. `control`,
/// `interactive`, `verification` and `canonical_write` are never in this list
/// and are therefore never shed when a pool is exhausted; the audit-critical
/// lane is not an I14.1 work class and is not shed either.
pub const SHEDDING_ORDER: [AdmissionClass; 5] = [
    AdmissionClass::Normal(NormalWorkClass::Maintenance),
    AdmissionClass::Normal(NormalWorkClass::Reporting),
    AdmissionClass::Normal(NormalWorkClass::Swarm),
    AdmissionClass::Normal(NormalWorkClass::ModelJob),
    AdmissionClass::Normal(NormalWorkClass::NormalBackground),
];

/// One I14.1 work class, or the separately named audit-critical lane.
///
/// This is a carrier over the frozen [`NormalWorkClass`] vocabulary, not a
/// second class registry: the only way to name a normal class is to name a
/// `NormalWorkClass` variant, so a class outside the frozen vocabulary is
/// unrepresentable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AdmissionClass {
    /// The reserved `control` class. It draws only from its own pool, which no
    /// normal class can borrow (I14.3).
    Control,
    /// One of the eight normal I14.1 classes.
    Normal(NormalWorkClass),
    /// An audit-critical event. I14.1 does not name it as a work class; the
    /// contract names it separately as the class of event that must remain
    /// recorded through an overload, so it has its own non-borrowable lane and
    /// is never in [`SHEDDING_ORDER`].
    AuditCritical,
}

impl AdmissionClass {
    /// Returns the exact I14.1 spelling of this class as declared by the
    /// governing documents.
    ///
    /// This is a projection for receipts and audit evidence, not a parse entry
    /// point: the closed [`NormalWorkClass`] variants and the typed admission
    /// methods are the only validated constructors.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Normal(NormalWorkClass::Interactive) => "interactive",
            Self::Normal(NormalWorkClass::Verification) => "verification",
            Self::Normal(NormalWorkClass::CanonicalWrite) => "canonical_write",
            Self::Normal(NormalWorkClass::NormalBackground) => "normal_background",
            Self::Normal(NormalWorkClass::ModelJob) => "model_jobs",
            Self::Normal(NormalWorkClass::Swarm) => "swarm",
            Self::Normal(NormalWorkClass::Reporting) => "reporting",
            Self::Normal(NormalWorkClass::Maintenance) => "maintenance",
            Self::AuditCritical => "audit_critical",
        }
    }

    /// Returns whether this class is sheddable when its own pool is exhausted.
    ///
    /// Exactly the [`SHEDDING_ORDER`] classes are sheddable. The reserved
    /// control partition, the four protected classes, and the audit-critical
    /// lane return `false` and are never shed by pool pressure.
    #[must_use]
    pub const fn is_sheddable(self) -> bool {
        match self {
            Self::Normal(
                NormalWorkClass::Maintenance
                | NormalWorkClass::Reporting
                | NormalWorkClass::Swarm
                | NormalWorkClass::ModelJob
                | NormalWorkClass::NormalBackground,
            ) => true,
            Self::Control
            | Self::AuditCritical
            | Self::Normal(
                NormalWorkClass::Interactive
                | NormalWorkClass::Verification
                | NormalWorkClass::CanonicalWrite,
            ) => false,
        }
    }
}

/// The four bounds I14.1 declares for one work class.
///
/// No value here is an Architecture or Kernel default: I14.2 states the numbers
/// are `runtime.toml` defaults, so every bound is supplied by the installed
/// operator profile and an absent or incomplete profile fails closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkPoolBudget {
    /// Maximum mailbox items: admitted units waiting to start execution.
    pub max_items: usize,
    /// Maximum mailbox bytes held by those admitted units.
    pub max_bytes: u64,
    /// Maximum units simultaneously holding an execution slot.
    pub max_concurrency: usize,
    /// Deadline profile applied to each unit of this class, in milliseconds
    /// after admission.
    pub deadline_unix_ms: u64,
}

impl WorkPoolBudget {
    /// Validates that every declared bound is a usable positive bound.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] naming `field` when any bound is
    /// zero, which would make the pool unbounded in that dimension.
    pub fn validate(self, field: &'static str) -> Result<(), KernelError> {
        if self.max_items == 0 {
            return Err(KernelError::InvalidField {
                field,
                reason: "max_items must be greater than zero",
            });
        }
        if self.max_bytes == 0 {
            return Err(KernelError::InvalidField {
                field,
                reason: "max_bytes must be greater than zero",
            });
        }
        if self.max_concurrency == 0 {
            return Err(KernelError::InvalidField {
                field,
                reason: "max_concurrency must be greater than zero",
            });
        }
        if self.deadline_unix_ms == 0 {
            return Err(KernelError::InvalidField {
                field,
                reason: "deadline_unix_ms must be greater than zero",
            });
        }
        Ok(())
    }
}

/// The installed I14.1 pool budget profile: one [`WorkPoolBudget`] per class
/// plus the non-sheddable audit-critical lane.
///
/// A caller constructs this from its own runtime configuration and hands it to
/// [`WorkClassScheduler::new`]. The Kernel never fabricates a default profile,
/// because I14.2 keeps these numbers outside Architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkClassBudgets {
    /// Reserved control pool. Never borrowed by normal work (I14.3).
    pub control: WorkPoolBudget,
    /// Interactive and named-read pool.
    pub interactive: WorkPoolBudget,
    /// Verification pool; its finish and proof work is preserved under
    /// pressure (I14.2).
    pub verification: WorkPoolBudget,
    /// Canonical-write pool; durable stage or backpressure (I14.2).
    pub canonical_write: WorkPoolBudget,
    /// Ordinary background pool; rebuildable work is paused or dropped first
    /// (I14.2).
    pub normal_background: WorkPoolBudget,
    /// Model-job pool; checkpoint or deny (I14.2).
    pub model_jobs: WorkPoolBudget,
    /// Swarm pool; stop admission and replan (I14.2).
    pub swarm: WorkPoolBudget,
    /// Reporting pool; regenerate later (I14.2).
    pub reporting: WorkPoolBudget,
    /// Maintenance pool.
    pub maintenance: WorkPoolBudget,
    /// Audit-critical lane. Bounded like every other lane and never shed, so
    /// an audit-critical event remains recorded through an overload.
    pub audit_critical: WorkPoolBudget,
}

impl WorkClassBudgets {
    /// Returns the declared budget of one class.
    #[must_use]
    pub const fn budget(&self, class: AdmissionClass) -> WorkPoolBudget {
        match class {
            AdmissionClass::Control => self.control,
            AdmissionClass::Normal(NormalWorkClass::Interactive) => self.interactive,
            AdmissionClass::Normal(NormalWorkClass::Verification) => self.verification,
            AdmissionClass::Normal(NormalWorkClass::CanonicalWrite) => self.canonical_write,
            AdmissionClass::Normal(NormalWorkClass::NormalBackground) => self.normal_background,
            AdmissionClass::Normal(NormalWorkClass::ModelJob) => self.model_jobs,
            AdmissionClass::Normal(NormalWorkClass::Swarm) => self.swarm,
            AdmissionClass::Normal(NormalWorkClass::Reporting) => self.reporting,
            AdmissionClass::Normal(NormalWorkClass::Maintenance) => self.maintenance,
            AdmissionClass::AuditCritical => self.audit_critical,
        }
    }

    /// Validates every declared bound of the profile.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] naming the offending class when
    /// any of its four bounds is zero.
    pub fn validate(&self) -> Result<(), KernelError> {
        self.control.validate("work_class_budgets.control")?;
        self.interactive
            .validate("work_class_budgets.interactive")?;
        self.verification
            .validate("work_class_budgets.verification")?;
        self.canonical_write
            .validate("work_class_budgets.canonical_write")?;
        self.normal_background
            .validate("work_class_budgets.normal_background")?;
        self.model_jobs
            .validate("work_class_budgets.model_jobs")?;
        self.swarm.validate("work_class_budgets.swarm")?;
        self.reporting.validate("work_class_budgets.reporting")?;
        self.maintenance
            .validate("work_class_budgets.maintenance")?;
        self.audit_critical
            .validate("work_class_budgets.audit_critical")
    }
}

/// The exact declared bound of one pool that a request exceeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolLimit {
    /// The declared mailbox item bound.
    Items,
    /// The declared mailbox byte bound.
    Bytes,
    /// The declared execution bound.
    Concurrency,
}

/// Cancellation state carried in the admitted work record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationState {
    /// No cancellation has been requested for this unit.
    Live,
    /// Cancellation was requested; the unit may no longer start execution.
    CancelRequested,
}

/// Execution-axis state carried in the admitted work record. Admission and
/// execution are separate axes (I14.6), so a unit is never both queued and
/// running.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionState {
    /// Admitted and waiting in the bounded mailbox; execution may start.
    Queued,
    /// Holding one of the declared execution slots; a spawn may follow.
    Running,
}

/// One submitted work unit, before it is associated with a class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkAdmissionRequest {
    /// Stable identity of the submitted unit.
    pub work_id: String,
    /// Owner requesting admission.
    pub owner: String,
    /// Declared mailbox cost of this unit in bytes.
    pub bytes: u64,
    /// Declared retry budget carried into the admitted work record. Zero is a
    /// legitimate declared budget meaning "no retry".
    pub retry_budget: u32,
}

/// A typed refusal of one admission. No variant is a string or a generic code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkAdmissionRefusal {
    /// A required field of the admission request is blank or malformed.
    InvalidRequest {
        /// Offending field.
        field: &'static str,
        /// Stable reason.
        reason: &'static str,
    },
    /// No work-class pool profile is installed, so nothing may be admitted
    /// against a Kernel-invented default.
    ProfileAbsent,
    /// The same work identity is already admitted in some pool.
    IdentityConflict {
        /// Class the duplicate arrived for.
        class: AdmissionClass,
        /// Duplicate work identity.
        work_id: String,
    },
    /// A declared bound of this class's pool is exhausted.
    ///
    /// `bottleneck` carries the exact frozen I14 denominator observation when
    /// the exhausted dimension has an honest row there, and `None` for the byte
    /// and execution bounds, which the frozen denominator does not name. The
    /// disposition is the I14.4 answer and `work_outcome` is the I14.6 answer;
    /// `shedding_order` is the documented I14.2 order the caller sheds in, and
    /// is attached whether or not the refused class is itself sheddable.
    PoolExhausted {
        /// Class whose pool refused the unit.
        class: AdmissionClass,
        /// Refused work identity.
        work_id: String,
        /// The exhausted declared bound.
        limit: PoolLimit,
        /// Exact I14.3 bottleneck observation for the exhausted dimension.
        bottleneck: Option<BottleneckObservationV1>,
        /// I14.4 disposition for this refusal.
        disposition: BackpressureDisposition,
        /// I14.6 outcome for the submitted unit: `Shed` for a sheddable class,
        /// `NotAccepted` for a class that is never shed under pressure.
        work_outcome: I14WorkOutcome,
        /// The documented I14.2 shedding order, least protected class first.
        shedding_order: Vec<AdmissionClass>,
    },
    /// The unit's declared retry budget is exhausted, so it may not retry
    /// again under this identity (I14.8: no unbounded retries).
    RetryBudgetExhausted {
        /// Class of the exhausted unit.
        class: AdmissionClass,
        /// Work identity.
        work_id: String,
    },
    /// Cancellation has been requested for the unit, so it may no longer start
    /// execution. Cancellation propagates to the admitted unit through its own
    /// record rather than through a queue position.
    Cancelled {
        /// Class of the cancelled unit.
        class: AdmissionClass,
        /// Work identity.
        work_id: String,
    },
    /// The work identity is no longer admitted in its pool.
    NotAdmitted {
        /// Class the unit was admitted under.
        class: AdmissionClass,
        /// Work identity.
        work_id: String,
    },
}

impl WorkAdmissionRefusal {
    fn invalid(error: KernelError) -> Self {
        match error {
            KernelError::InvalidField { field, reason } => Self::InvalidRequest { field, reason },
            KernelError::Foundation(_) | KernelError::Receipt(_) | KernelError::RuntimeContract(_) => {
                Self::InvalidRequest {
                    field: "work_admission.request",
                    reason: "identity is not an accepted Kernel opaque identity",
                }
            }
            _ => Self::InvalidRequest {
                field: "work_admission.request",
                reason: "request identity is not admissible",
            },
        }
    }
}

/// Observed capacity of one pool against its declared bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolAvailability {
    /// The class this pool serves.
    pub class: AdmissionClass,
    /// Declared mailbox item bound.
    pub max_items: usize,
    /// Units currently held in the bounded mailbox.
    pub queued_items: usize,
    /// Declared mailbox byte bound.
    pub max_bytes: u64,
    /// Bytes currently held in the bounded mailbox.
    pub queued_bytes: u64,
    /// Declared execution bound.
    pub max_concurrency: usize,
    /// Units currently holding an execution slot.
    pub running: usize,
    /// Declared deadline profile in milliseconds after admission.
    pub deadline_unix_ms: u64,
}

/// A snapshot of one admitted work record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedWorkRecord {
    /// The I14.1 class the unit was admitted under.
    pub class: AdmissionClass,
    /// Stable work identity.
    pub work_id: String,
    /// Owner the unit was admitted for.
    pub owner: String,
    /// Declared mailbox cost in bytes.
    pub bytes: u64,
    /// Retries still available under the declared budget.
    pub retries_remaining: u32,
    /// Execution-axis state.
    pub execution: ExecutionState,
    /// Cancellation state.
    pub cancellation: CancellationState,
    /// Admission time in Unix milliseconds.
    pub admitted_at_unix_ms: u64,
    /// Deadline of the pool's declared deadline profile in Unix milliseconds.
    pub deadline_unix_ms: u64,
}

/// The mutable admitted record held by one pool.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PoolRecord {
    class: AdmissionClass,
    owner: String,
    bytes: u64,
    retries_remaining: u32,
    execution: ExecutionState,
    cancellation: CancellationState,
    admitted_at_unix_ms: u64,
    deadline_unix_ms: u64,
}

/// One independent I14.1 work-class pool with its declared bounds.
///
/// A pool is never shared: acquiring from one pool neither observes nor consumes
/// another, so saturating `normal_background` or `model_jobs` leaves the
/// reserved `control` pool and the `interactive` pool untouched.
#[derive(Debug)]
pub struct WorkPool {
    class: AdmissionClass,
    budget: WorkPoolBudget,
    records: Mutex<BTreeMap<String, PoolRecord>>,
}

impl WorkPool {
    /// Creates one pool for one class from its declared bounds.
    #[must_use]
    pub const fn new(class: AdmissionClass, budget: WorkPoolBudget) -> Self {
        Self {
            class,
            budget,
            records: Mutex::new(BTreeMap::new()),
        }
    }

    /// Returns the class this pool serves.
    #[must_use]
    pub const fn class(&self) -> AdmissionClass {
        self.class
    }

    /// Returns the declared bounds of this pool.
    #[must_use]
    pub const fn budget(&self) -> WorkPoolBudget {
        self.budget
    }

    /// Returns the observed capacity of this pool against its declared bounds.
    #[must_use]
    pub fn availability(&self) -> PoolAvailability {
        let records = self.lock();
        let (queued_items, queued_bytes, running) = totals(&records);
        PoolAvailability {
            class: self.class,
            max_items: self.budget.max_items,
            queued_items,
            max_bytes: self.budget.max_bytes,
            queued_bytes,
            max_concurrency: self.budget.max_concurrency,
            running,
            deadline_unix_ms: self.budget.deadline_unix_ms,
        }
    }

    /// Admits one submitted unit of this pool's class into the bounded mailbox.
    ///
    /// The check and the insert happen under one lock, so a full mailbox can
    /// never grow past its declared item or byte bound.
    fn admit(
        self: &Arc<Self>,
        request: &WorkAdmissionRequest,
        now_unix_ms: u64,
    ) -> Result<AdmittedWork, WorkAdmissionRefusal> {
        validate_id(&request.work_id, "work_admission.work_id")
            .map_err(WorkAdmissionRefusal::invalid)?;
        validate_id(&request.owner, "work_admission.owner")
            .map_err(WorkAdmissionRefusal::invalid)?;
        if request.bytes == 0 {
            return Err(WorkAdmissionRefusal::InvalidRequest {
                field: "work_admission.bytes",
                reason: "must be positive",
            });
        }
        let mut records = self.lock();
        if records.contains_key(request.work_id.as_str()) {
            return Err(WorkAdmissionRefusal::IdentityConflict {
                class: self.class,
                work_id: request.work_id.clone(),
            });
        }
        let (queued_items, queued_bytes, _) = totals(&records);
        self.check_mailbox(request, queued_items, queued_bytes)?;
        records.insert(
            request.work_id.clone(),
            PoolRecord {
                class: self.class,
                owner: request.owner.clone(),
                bytes: request.bytes,
                retries_remaining: request.retry_budget,
                execution: ExecutionState::Queued,
                cancellation: CancellationState::Live,
                admitted_at_unix_ms: now_unix_ms,
                deadline_unix_ms: now_unix_ms.saturating_add(self.budget.deadline_unix_ms),
            },
        );
        drop(records);
        Ok(AdmittedWork {
            pool: Arc::clone(self),
            work_id: request.work_id.clone(),
        })
    }

    fn check_mailbox(
        &self,
        request: &WorkAdmissionRequest,
        queued_items: usize,
        queued_bytes: u64,
    ) -> Result<(), WorkAdmissionRefusal> {
        if queued_items >= self.budget.max_items {
            return Err(self.pool_exhausted(
                request,
                PoolLimit::Items,
                Some(BottleneckObservationV1 {
                    bottleneck: FRONT_DOOR_BOTTLENECK,
                    unit: FRONT_DOOR_BOTTLENECK.unit(),
                    requested_amount: 1,
                    availability: BottleneckAvailability::Exhausted {
                        available_amount: 0,
                    },
                    coverage_state: BottleneckCoverageState::Claimed,
                }),
            ));
        }
        let free_bytes = self.budget.max_bytes.saturating_sub(queued_bytes);
        if request.bytes > free_bytes {
            return Err(self.pool_exhausted(request, PoolLimit::Bytes, None));
        }
        Ok(())
    }

    fn pool_exhausted(
        &self,
        request: &WorkAdmissionRequest,
        limit: PoolLimit,
        bottleneck: Option<BottleneckObservationV1>,
    ) -> WorkAdmissionRefusal {
        WorkAdmissionRefusal::PoolExhausted {
            class: self.class,
            work_id: request.work_id.clone(),
            limit,
            bottleneck,
            disposition: BackpressureDisposition::Busy,
            work_outcome: if self.class.is_sheddable() {
                I14WorkOutcome::Shed
            } else {
                I14WorkOutcome::NotAccepted
            },
            shedding_order: SHEDDING_ORDER.to_vec(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, PoolRecord>> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Removes the record of one work identity, if it is still admitted.
    fn release(&self, work_id: &str) {
        self.lock().remove(work_id);
    }
}

/// The handle of one admitted work unit.
///
/// It is the only way to reach the unit's capacity, its retry budget and its
/// cancellation state, so a spawn, a retry or a cancellation can never bypass
/// the admitted record. Releasing is automatic: dropping the handle removes the
/// record and returns every item, byte and execution slot it held.
#[derive(Debug)]
pub struct AdmittedWork {
    pool: Arc<WorkPool>,
    work_id: String,
}

impl AdmittedWork {
    /// Returns the I14.1 class this unit was admitted under.
    #[must_use]
    pub fn class(&self) -> AdmissionClass {
        self.pool.class
    }

    /// Returns the admitted work identity.
    #[must_use]
    pub fn work_id(&self) -> &str {
        &self.work_id
    }

    /// Returns a snapshot of the admitted work record.
    ///
    /// # Errors
    ///
    /// Returns [`WorkAdmissionRefusal::NotAdmitted`] when the unit is no longer
    /// admitted in its pool.
    pub fn record(&self) -> Result<AdmittedWorkRecord, WorkAdmissionRefusal> {
        let records = self.pool.lock();
        let record = records
            .get(self.work_id.as_str())
            .ok_or_else(|| WorkAdmissionRefusal::NotAdmitted {
                class: self.pool.class,
                work_id: self.work_id.clone(),
            })?;
        Ok(AdmittedWorkRecord {
            class: record.class,
            work_id: self.work_id.clone(),
            owner: record.owner.clone(),
            bytes: record.bytes,
            retries_remaining: record.retries_remaining,
            execution: record.execution,
            cancellation: record.cancellation,
            admitted_at_unix_ms: record.admitted_at_unix_ms,
            deadline_unix_ms: record.deadline_unix_ms,
        })
    }

    /// Transitions the unit onto the execution axis, which is the last
    /// pre-spawn gate: the call is refused when the pool's declared execution
    /// bound is held or when cancellation has been requested.
    ///
    /// # Errors
    ///
    /// Returns [`WorkAdmissionRefusal::PoolExhausted`] with
    /// [`PoolLimit::Concurrency`] when every declared execution slot is held,
    /// [`WorkAdmissionRefusal::Cancelled`] when cancellation has been requested,
    /// and [`WorkAdmissionRefusal::NotAdmitted`] when the unit has already left
    /// its pool.
    pub fn start_running(&mut self) -> Result<(), WorkAdmissionRefusal> {
        let mut records = self.pool.lock();
        let record = records
            .get_mut(self.work_id.as_str())
            .ok_or_else(|| WorkAdmissionRefusal::NotAdmitted {
                class: self.pool.class,
                work_id: self.work_id.clone(),
            })?;
        if record.cancellation == CancellationState::CancelRequested {
            return Err(WorkAdmissionRefusal::Cancelled {
                class: self.pool.class,
                work_id: self.work_id.clone(),
            });
        }
        let (_, _, running) = totals(&records);
        if running >= self.pool.budget.max_concurrency {
            return Err(self.pool.pool_exhausted(
                &WorkAdmissionRequest {
                    work_id: self.work_id.clone(),
                    owner: record.owner.clone(),
                    bytes: record.bytes,
                    retry_budget: record.retries_remaining,
                },
                PoolLimit::Concurrency,
                None,
            ));
        }
        record.execution = ExecutionState::Running;
        Ok(())
    }

    /// Consumes one retry from the unit's declared budget.
    ///
    /// # Errors
    ///
    /// Returns [`WorkAdmissionRefusal::RetryBudgetExhausted`] when the declared
    /// budget is already spent, so the unit never retries unboundedly (I14.8),
    /// and [`WorkAdmissionRefusal::NotAdmitted`] when the unit has already left
    /// its pool. On refusal the remaining budget is unchanged, so the caller
    /// never observes a budget that was not actually charged.
    pub fn consume_retry(&mut self) -> Result<u32, WorkAdmissionRefusal> {
        let mut records = self.pool.lock();
        let record = records
            .get_mut(self.work_id.as_str())
            .ok_or_else(|| WorkAdmissionRefusal::NotAdmitted {
                class: self.pool.class,
                work_id: self.work_id.clone(),
            })?;
        if record.retries_remaining == 0 {
            return Err(WorkAdmissionRefusal::RetryBudgetExhausted {
                class: self.pool.class,
                work_id: self.work_id.clone(),
            });
        }
        record.retries_remaining -= 1;
        Ok(record.retries_remaining)
    }

    /// Requests cancellation of this unit.
    ///
    /// The request is recorded on the admitted work record itself, so it
    /// reaches the unit: a later [`Self::start_running`] is refused, and no
    /// later spawn can be admitted from this handle.
    ///
    /// # Errors
    ///
    /// Returns [`WorkAdmissionRefusal::NotAdmitted`] when the unit has already
    /// left its pool.
    pub fn cancel(&mut self) -> Result<(), WorkAdmissionRefusal> {
        let mut records = self.pool.lock();
        let record = records
            .get_mut(self.work_id.as_str())
            .ok_or_else(|| WorkAdmissionRefusal::NotAdmitted {
                class: self.pool.class,
                work_id: self.work_id.clone(),
            })?;
        record.cancellation = CancellationState::CancelRequested;
        Ok(())
    }
}

impl Drop for AdmittedWork {
    fn drop(&mut self) {
        self.pool.release(self.work_id.as_str());
    }
}

/// The Kernel's I14.1 work-class admission scheduler.
///
/// It owns one independent [`WorkPool`] per class, including the reserved
/// `control` pool and the non-sheddable audit-critical lane. Every submitted
/// unit is associated with its class through this scheduler before any process
/// or task spawn.
#[derive(Debug)]
pub struct WorkClassScheduler {
    control: Arc<WorkPool>,
    interactive: Arc<WorkPool>,
    verification: Arc<WorkPool>,
    canonical_write: Arc<WorkPool>,
    normal_background: Arc<WorkPool>,
    model_jobs: Arc<WorkPool>,
    swarm: Arc<WorkPool>,
    reporting: Arc<WorkPool>,
    maintenance: Arc<WorkPool>,
    audit_critical: Arc<WorkPool>,
}

impl WorkClassScheduler {
    /// Installs one bounded pool per class from the declared budget profile.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] naming the offending class when
    /// any of its four declared bounds is zero.
    pub fn new(budgets: WorkClassBudgets) -> Result<Self, KernelError> {
        budgets.validate()?;
        Ok(Self {
            control: Arc::new(WorkPool::new(AdmissionClass::Control, budgets.control)),
            interactive: Arc::new(WorkPool::new(
                AdmissionClass::Normal(NormalWorkClass::Interactive),
                budgets.interactive,
            )),
            verification: Arc::new(WorkPool::new(
                AdmissionClass::Normal(NormalWorkClass::Verification),
                budgets.verification,
            )),
            canonical_write: Arc::new(WorkPool::new(
                AdmissionClass::Normal(NormalWorkClass::CanonicalWrite),
                budgets.canonical_write,
            )),
            normal_background: Arc::new(WorkPool::new(
                AdmissionClass::Normal(NormalWorkClass::NormalBackground),
                budgets.normal_background,
            )),
            model_jobs: Arc::new(WorkPool::new(
                AdmissionClass::Normal(NormalWorkClass::ModelJob),
                budgets.model_jobs,
            )),
            swarm: Arc::new(WorkPool::new(
                AdmissionClass::Normal(NormalWorkClass::Swarm),
                budgets.swarm,
            )),
            reporting: Arc::new(WorkPool::new(
                AdmissionClass::Normal(NormalWorkClass::Reporting),
                budgets.reporting,
            )),
            maintenance: Arc::new(WorkPool::new(
                AdmissionClass::Normal(NormalWorkClass::Maintenance),
                budgets.maintenance,
            )),
            audit_critical: Arc::new(WorkPool::new(
                AdmissionClass::AuditCritical,
                budgets.audit_critical,
            )),
        })
    }

    /// Returns the installed pool of one class.
    #[must_use]
    pub fn pool(&self, class: AdmissionClass) -> &Arc<WorkPool> {
        match class {
            AdmissionClass::Control => &self.control,
            AdmissionClass::Normal(NormalWorkClass::Interactive) => &self.interactive,
            AdmissionClass::Normal(NormalWorkClass::Verification) => &self.verification,
            AdmissionClass::Normal(NormalWorkClass::CanonicalWrite) => &self.canonical_write,
            AdmissionClass::Normal(NormalWorkClass::NormalBackground) => &self.normal_background,
            AdmissionClass::Normal(NormalWorkClass::ModelJob) => &self.model_jobs,
            AdmissionClass::Normal(NormalWorkClass::Swarm) => &self.swarm,
            AdmissionClass::Normal(NormalWorkClass::Reporting) => &self.reporting,
            AdmissionClass::Normal(NormalWorkClass::Maintenance) => &self.maintenance,
            AdmissionClass::AuditCritical => &self.audit_critical,
        }
    }

    /// Returns the documented I14.2 load-shedding order, least protected class
    /// first.
    #[must_use]
    pub fn shedding_order(&self) -> Vec<AdmissionClass> {
        SHEDDING_ORDER.to_vec()
    }

    /// Admits one submitted unit into the pool of its declared class.
    ///
    /// This is the pre-spawn admission point: no process or task may be started
    /// from a work unit that has no handle returned here. The reserved `control`
    /// pool, every normal pool and the audit-critical lane are separate, so a
    /// controlled `normal_background` or `model_jobs` backlog cannot consume
    /// the capacity a `control` or `interactive` unit draws from.
    ///
    /// # Errors
    ///
    /// Returns [`WorkAdmissionRefusal::InvalidRequest`] for a malformed request,
    /// [`WorkAdmissionRefusal::IdentityConflict`] for a duplicate work
    /// identity, and [`WorkAdmissionRefusal::PoolExhausted`] when a declared
    /// bound of that class's pool is exhausted.
    pub fn admit(
        &self,
        class: AdmissionClass,
        request: &WorkAdmissionRequest,
        now_unix_ms: u64,
    ) -> Result<AdmittedWork, WorkAdmissionRefusal> {
        self.pool(class).admit(request, now_unix_ms)
    }
}

/// Sums the queued item count, the queued byte cost and the running count of
/// one pool's admitted records. Only records still on the execution axis's
/// queue leg count against the mailbox bounds.
fn totals(records: &BTreeMap<String, PoolRecord>) -> (usize, u64, usize) {
    records.values().fold(
        (0_usize, 0_u64, 0_usize),
        |(items, bytes, running), record| match record.execution {
            ExecutionState::Queued => (
                items + 1,
                bytes.saturating_add(record.bytes),
                running,
            ),
            ExecutionState::Running => (items, bytes, running + 1),
        },
    )
}
