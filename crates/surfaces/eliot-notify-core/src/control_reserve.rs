//! Notification control-reserve partitions for persistent inbox items.
//!
//! Issue #1679, W3 notification wave: the existing Governor notification/inbox
//! owner, the A-10 role-filtered one-shot notification delivery core with a
//! protected delivery path, enforces disjoint normal-workload and
//! protected-control partitions for its frozen bottleneck
//! ([`NOTIFICATION_INBOX_BOTTLENECK`]). Normal work can saturate the normal
//! partition without consuming protected cancellation/recovery capacity: an
//! admitted cancellation or recovery record keeps the protected notification
//! path while ordinary work observes exhaustion. Only [`NormalWorkClass`]
//! operations typecheck on the normal acquisition path and only
//! [`ControlOperationClass`] operations typecheck on the protected path, so
//! ordinary work cannot reach protected notification capacity by relabelling
//! its priority or class.
//!
//! Exhausted normal capacity renders as a versioned
//! [`I14BackpressureResponseV1`] with disposition `BUSY` naming exactly the
//! saturated notification bottleneck in its exact unit: persistent inbox
//! items in items. `STORAGE_BACKPRESSURE` is not used here: the existing
//! [`I14BackpressureResponseV1::validate`] pins that disposition to the ORS
//! durable queue bytes, so a notification observation would fail closed
//! instead of emitting evidence. Every response is validated by the existing
//! [`I14BackpressureResponseV1::validate`] before it is returned, so an
//! inconsistent observation fails closed instead of emitting a
//! disposition-only or generic queue-full answer. The response method reads
//! the live reserve it reports and refuses while that reserve still admits
//! the request, so pressure evidence is never manufactured.
//!
//! W4 notification wave: every [`NotifyPermit`] is owner-issued non-clone
//! evidence bound to capacity class, bottleneck/unit/granted amount, typed
//! operation, operation identity, owner and the typed [`AuthorityEpoch`]
//! observed at acquisition, mirroring the ORS evidence grade. Every denial
//! names the exact bottleneck, shed work and observed epoch. A stale epoch, a
//! changed operation or a changed owner fails before consumption because the
//! evidence no longer matches the current owner state; there is no
//! epoch-blind permit to replay.
//!
//! The claimed notification dimension publishes its live partition evidence
//! through [`NotifyReserve::publish_owner_rows`] as one validated
//! [`BottleneckCapacityProfile`] row naming exactly its own bottleneck, in
//! frozen contract order. The row is re-validated by the existing
//! [`BottleneckCapacityProfile::validate`] before it is returned, so a
//! missing owner, generation, physical total, protected partition,
//! enforcement, proof, evidence or invalidation reference fails here rather
//! than joining the Kernel profile composition as a claimed guarantee. Rows
//! for any other bottleneck are never produced here: one owner's numbers are
//! never presented as proof for another dimension.
//!
//! This module has no production caller yet (STITCH): it publishes the owner
//! evidence the notification profile composition will join. There is no
//! emergency partition here; recording reserve loss stays with the front-door
//! last-resort slot until a later wave wires notification-side loss
//! reporting.
//! DISCLOSED LIMIT: `profile_revision` on the response is caller-supplied
//! metadata echoed into the directive; the `Current` currentness claim refers
//! to the live-observed saturation at call time, not to a re-read of the
//! profile revision. Full installed-saturation proof stays #11 Product scope.

use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_contracts::{ArtifactId, AuthorityEpoch, OperationId};
use eliot_runtime_contracts::{
    AffectedOperationClass, BackpressureDisposition, BottleneckAvailability,
    BottleneckCapacityProfile, BottleneckCoverageState, BottleneckObservationV1,
    CapacityBottleneck, CapacityClass, CapacityEnforcement, CapacityLimit, CapacityUnit,
    ControlOperationClass, EarliestRecoveryCondition, EvidenceCoverageState,
    HumanActionRequirement, I14_BACKPRESSURE_RESPONSE_VERSION, I14BackpressureCause,
    I14BackpressureResponseV1, I14CurrentnessState, I14EscalationCondition, I14ForbiddenAction,
    I14RecoveryAction, I14RecoveryDirectiveV1, I14RequiredAuthority, I14ResolutionState,
    I14WorkOutcome, NormalWorkClass, RecoveryCommitStatus, StatePreservationStatus,
    frozen_bottleneck_owner_map,
};
use thiserror::Error;

/// The exact persistent notification/inbox bottleneck enforced by
/// [`NotifyReserve`].
pub const NOTIFICATION_INBOX_BOTTLENECK: CapacityBottleneck =
    CapacityBottleneck::NotificationPersistentInbox;

/// Typed notification reserve failures. None grants semantic or completion
/// authority.
#[derive(Debug, Error)]
pub enum NotifyReserveError {
    /// An owner or operation identity is blank or malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Failing field name.
        field: &'static str,
        /// Why the field failed.
        reason: &'static str,
    },
    /// The existing contract rejected an assembled notification backpressure
    /// response.
    #[error("runtime contract rejected notification reserve response: {0}")]
    Contract(String),
    /// The normal partition cannot satisfy the request; the protected
    /// partition is untouched.
    #[error(
        "notification normal capacity exhausted for {bottleneck:?}: work {work_class:?} operation {operation_id} owned by {owner} epoch {epoch:?}"
    )]
    NormalCapacityExhausted {
        /// Bottleneck whose normal partition is saturated.
        bottleneck: CapacityBottleneck,
        /// Shed normal work class.
        work_class: NormalWorkClass,
        /// Operation that was not admitted.
        operation_id: String,
        /// Requesting owner.
        owner: String,
        /// Authority epoch observed at denial.
        epoch: AuthorityEpoch,
    },
    /// The protected partition cannot satisfy the request.
    #[error(
        "notification protected reserve exhausted for {bottleneck:?}: control operation {operation:?} operation {operation_id} owned by {owner} epoch {epoch:?}"
    )]
    ProtectedReserveExhausted {
        /// Bottleneck whose protected partition is saturated.
        bottleneck: CapacityBottleneck,
        /// Control operation that was not admitted.
        operation: ControlOperationClass,
        /// Operation that was not admitted.
        operation_id: String,
        /// Requesting owner.
        owner: String,
        /// Authority epoch observed at denial.
        epoch: AuthorityEpoch,
    },
}

/// Typed operation identity carried by every [`NotifyPermit`].
///
/// The variant determines the only admissible [`CapacityClass`]: a normal work
/// class cannot name a protected operation and vice versa, so ordinary work
/// fails to typecheck against the protected acquisition path instead of
/// failing at runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotifyPermitOperation {
    /// Ordinary workload operation.
    Normal(NormalWorkClass),
    /// Protected cancellation/recovery operation.
    Protected(ControlOperationClass),
}

impl NotifyPermitOperation {
    /// Returns the capacity class this operation draws from.
    #[must_use]
    pub const fn capacity_class(self) -> CapacityClass {
        match self {
            Self::Normal(_) => CapacityClass::NormalWorkload,
            Self::Protected(_) => CapacityClass::ProtectedControl,
        }
    }
}

/// Composition-resolved references identifying one notification
/// owner-evidence publication: the live partition capacities read from the
/// reserve itself and their physical total, and the
/// [`CapacityEnforcement::ConfigurationPartition`] mechanism those partitions
/// are held under. The composition supplies the references that identify the
/// observation: its own owner-generation reference for the notification/inbox
/// owner, the independent proof-profile reference, and the current evidence
/// and invalidation references. Both halves are required:
/// [`NotifyReserve::publish_owner_rows`] fails closed through the existing
/// [`BottleneckCapacityProfile::validate`] when any reference is missing or
/// non-canonical, so the composition must resolve canonical (strictly
/// ascending, duplicate-free) reference sets rather than have them defaulted
/// or sorted here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyOwnerEvidenceContext {
    /// Owner generation/revision reference for the notification/inbox owner.
    pub owner_generation_ref: String,
    /// Independent proof-profile reference produced for the notification
    /// dimension.
    pub proof_profile_ref: String,
    /// Current owner evidence references supporting the published row.
    pub evidence_refs: Vec<String>,
    /// Exact invalidation set of the published row.
    pub invalidation_set: Vec<String>,
}

#[derive(Debug)]
struct NotifyReserveInner {
    normal_capacity: u64,
    protected_capacity: u64,
    normal_in_flight: AtomicU64,
    protected_in_flight: AtomicU64,
}

/// The notification control reserve: disjoint normal/protected partitions for
/// persistent inbox items, owned by the existing Governor notification/inbox
/// owner.
///
/// Acquiring from one partition never observes or consumes the other:
/// saturating normal inbox items leaves the full protected capacity available
/// for admitted cancellation/recovery records and vice versa. Acquisition is
/// non-blocking and atomic; release is automatic when the returned
/// [`NotifyPermit`] drops.
#[derive(Clone, Debug)]
pub struct NotifyReserve {
    inner: Arc<NotifyReserveInner>,
}

/// One held notification capacity permit, bound to class, operation, owner
/// and Authority Epoch. Releasing is automatic on drop and returns exactly
/// the consumed partition.
///
/// The permit is bound to the typed Authority Epoch the caller resolved at
/// acquisition: evidence from a fenced epoch never authorizes consumption
/// under the current one. Permits are deliberately not [`Clone`]: duplicating
/// a permit handle must never duplicate the underlying capacity.
#[derive(Debug)]
pub struct NotifyPermit {
    inner: Arc<NotifyReserveInner>,
    class: CapacityClass,
    operation: NotifyPermitOperation,
    operation_id: String,
    owner: String,
    epoch: AuthorityEpoch,
}

impl NotifyPermit {
    /// Returns the capacity class (partition) this permit holds.
    #[must_use]
    pub const fn capacity_class(&self) -> CapacityClass {
        self.class
    }

    /// Returns the bottleneck this permit was granted from.
    #[must_use]
    pub const fn bottleneck(&self) -> CapacityBottleneck {
        NOTIFICATION_INBOX_BOTTLENECK
    }

    /// Returns the exact unit this permit was granted in.
    #[must_use]
    pub const fn unit(&self) -> CapacityUnit {
        NOTIFICATION_INBOX_BOTTLENECK.unit()
    }

    /// Returns the amount held in the bottleneck's exact unit (items).
    #[must_use]
    pub const fn amount(&self) -> u64 {
        1
    }

    /// Returns the typed operation identity carried by this permit.
    #[must_use]
    pub const fn operation(&self) -> NotifyPermitOperation {
        self.operation
    }

    /// Returns the operation identity this permit was granted for.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the owner this permit was granted to.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the Authority Epoch bound at acquisition.
    #[must_use]
    pub const fn epoch(&self) -> AuthorityEpoch {
        self.epoch
    }
}

impl Drop for NotifyPermit {
    fn drop(&mut self) {
        let slot = match self.class {
            CapacityClass::NormalWorkload => &self.inner.normal_in_flight,
            _ => &self.inner.protected_in_flight,
        };
        debug_assert!(
            slot.load(Ordering::Acquire) >= 1,
            "notification permit drop without a held partition item"
        );
        slot.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Atomically adds one item to `slot` unless `capacity` would be exceeded.
fn cas_add_one(slot: &AtomicU64, capacity: u64) -> bool {
    let mut observed = slot.load(Ordering::Acquire);
    loop {
        let Some(next) = observed.checked_add(1) else {
            return false;
        };
        if next > capacity {
            return false;
        }
        match slot.compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(current) => observed = current,
        }
    }
}

/// Rejects blank, control-character or overlong owner/operation identities.
fn validate_text(value: &str, field: &'static str) -> Result<(), NotifyReserveError> {
    if value.trim().is_empty() {
        return Err(NotifyReserveError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(NotifyReserveError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > 1_024 {
        return Err(NotifyReserveError::InvalidField {
            field,
            reason: "must not exceed 1024 UTF-8 bytes",
        });
    }
    Ok(())
}

impl NotifyReserve {
    /// Creates a notification reserve with disjoint normal and protected
    /// partitions for persistent inbox items.
    ///
    /// Normal work draws only from the normal inbox items; admitted
    /// cancellation/recovery draws only from the protected inbox items.
    /// Neither class can borrow from the other.
    ///
    /// # Errors
    ///
    /// Returns [`NotifyReserveError::InvalidField`] when either inbox
    /// partition capacity is zero.
    pub fn partitioned(
        normal_inbox_items: u64,
        protected_inbox_items: u64,
    ) -> Result<Self, NotifyReserveError> {
        if normal_inbox_items == 0 {
            return Err(NotifyReserveError::InvalidField {
                field: "notify_reserve.normal_inbox_items",
                reason: "must be greater than zero",
            });
        }
        if protected_inbox_items == 0 {
            return Err(NotifyReserveError::InvalidField {
                field: "notify_reserve.protected_inbox_items",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            inner: Arc::new(NotifyReserveInner {
                normal_capacity: normal_inbox_items,
                protected_capacity: protected_inbox_items,
                normal_in_flight: AtomicU64::new(0),
                protected_in_flight: AtomicU64::new(0),
            }),
        })
    }

    /// Returns the configured normal inbox-item partition capacity.
    #[must_use]
    pub fn normal_inbox_capacity(&self) -> u64 {
        self.inner.normal_capacity
    }

    /// Returns the configured protected inbox-item partition capacity.
    #[must_use]
    pub fn protected_inbox_capacity(&self) -> u64 {
        self.inner.protected_capacity
    }

    /// Returns the currently available normal inbox items.
    #[must_use]
    pub fn available_normal_inbox(&self) -> u64 {
        self.inner
            .normal_capacity
            .saturating_sub(self.inner.normal_in_flight.load(Ordering::Acquire))
    }

    /// Returns the currently available protected inbox items.
    #[must_use]
    pub fn available_protected_inbox(&self) -> u64 {
        self.inner
            .protected_capacity
            .saturating_sub(self.inner.protected_in_flight.load(Ordering::Acquire))
    }

    /// Attempts to acquire one normal inbox item without blocking.
    ///
    /// Only [`NormalWorkClass`] operations typecheck here, so protected
    /// notification inbox capacity is unreachable through this path by
    /// construction. The granted permit binds `epoch`; a caller presenting it
    /// under a different epoch holds evidence that no longer matches the
    /// current owner state.
    ///
    /// # Errors
    ///
    /// Returns [`NotifyReserveError::InvalidField`] for a blank
    /// owner/operation identity, or
    /// [`NotifyReserveError::NormalCapacityExhausted`] naming the inbox
    /// bottleneck, shed work and observed epoch when the normal partition is
    /// saturated. The protected partition is untouched in every case.
    pub fn try_acquire_normal_inbox(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
        epoch: AuthorityEpoch,
    ) -> Result<NotifyPermit, NotifyReserveError> {
        validate_text(owner, "notify_permit.owner")?;
        validate_text(operation_id, "notify_permit.operation_id")?;
        if !cas_add_one(&self.inner.normal_in_flight, self.inner.normal_capacity) {
            return Err(NotifyReserveError::NormalCapacityExhausted {
                bottleneck: NOTIFICATION_INBOX_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
                epoch,
            });
        }
        Ok(NotifyPermit {
            inner: self.inner.clone(),
            class: CapacityClass::NormalWorkload,
            operation: NotifyPermitOperation::Normal(work),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
        })
    }

    /// Attempts to acquire one protected inbox item without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here: ordinary work
    /// cannot name a protected operation and therefore cannot acquire this
    /// partition. This is the path an admitted cancellation/recovery record
    /// keeps while normal inbox work reports `BUSY`. The granted permit binds
    /// `epoch` so the recovery record proves it was admitted under the current
    /// owner state.
    ///
    /// # Errors
    ///
    /// Returns [`NotifyReserveError::InvalidField`] for a blank
    /// owner/operation identity, or
    /// [`NotifyReserveError::ProtectedReserveExhausted`] naming the inbox
    /// bottleneck, operation, owner, request and observed epoch when the
    /// protected partition is saturated.
    pub fn try_acquire_protected_inbox(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
        epoch: AuthorityEpoch,
    ) -> Result<NotifyPermit, NotifyReserveError> {
        validate_text(owner, "notify_permit.owner")?;
        validate_text(operation_id, "notify_permit.operation_id")?;
        if !cas_add_one(
            &self.inner.protected_in_flight,
            self.inner.protected_capacity,
        ) {
            return Err(NotifyReserveError::ProtectedReserveExhausted {
                bottleneck: NOTIFICATION_INBOX_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
                epoch,
            });
        }
        Ok(NotifyPermit {
            inner: self.inner.clone(),
            class: CapacityClass::ProtectedControl,
            operation: NotifyPermitOperation::Protected(operation),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
            epoch,
        })
    }

    /// Reports exhausted normal inbox items as a `BUSY` response naming
    /// exactly [`NOTIFICATION_INBOX_BOTTLENECK`].
    ///
    /// The response is built only while [`Self::available_normal_inbox`] is
    /// zero: pressure evidence is never manufactured for a partition that
    /// still admits work. The protected partition is not read and not
    /// claimed, so an admitted cancellation/recovery record keeps its path
    /// while this response is live. `BUSY` (not `STORAGE_BACKPRESSURE`) is
    /// the honest disposition: the existing contract validation pins
    /// `STORAGE_BACKPRESSURE` to the ORS durable queue bytes.
    ///
    /// # Errors
    ///
    /// Returns [`NotifyReserveError::InvalidField`] when normal inbox capacity
    /// remains or the operation identity is malformed, or
    /// [`NotifyReserveError::Contract`] when the assembled directive fails
    /// the existing contract validation.
    pub fn normal_inbox_exhaustion_response(
        &self,
        work: NormalWorkClass,
        operation_id: &str,
        profile_revision: ArtifactId,
    ) -> Result<I14BackpressureResponseV1, NotifyReserveError> {
        if self.available_normal_inbox() > 0 {
            return Err(NotifyReserveError::InvalidField {
                field: "notify_reserve.normal_inbox_items",
                reason: "normal inbox partition is not saturated; no pressure evidence to report",
            });
        }
        let operation =
            OperationId::new(operation_id).map_err(|_| NotifyReserveError::InvalidField {
                field: "notify_rejection.operation_id",
                reason: "must be a bounded non-blank reference",
            })?;
        NotifyRejectionParts {
            affected: AffectedOperationClass::Normal(work),
            observation: BottleneckObservationV1 {
                bottleneck: NOTIFICATION_INBOX_BOTTLENECK,
                unit: NOTIFICATION_INBOX_BOTTLENECK.unit(),
                requested_amount: 1,
                availability: BottleneckAvailability::Exhausted {
                    available_amount: 0,
                },
                coverage_state: BottleneckCoverageState::Claimed,
            },
            operation_id: Some(operation),
            profile_revision,
        }
        .into_response(
            BackpressureDisposition::Busy,
            I14WorkOutcome::NotAccepted,
            RecoveryCommitStatus::None,
        )
    }

    /// Publishes the live partition evidence for the notification dimension
    /// as one claimed [`BottleneckCapacityProfile`] row, in frozen contract
    /// order.
    ///
    /// The result carries exactly one row naming [`NOTIFICATION_INBOX_BOTTLENECK`]:
    /// the frozen owner the contract binds to that dimension, the exact
    /// bottleneck unit, the physical total and the disjoint normal and
    /// protected partitions read from this reserve. There is no emergency
    /// partition here, so none is claimed. The owner generation, proof
    /// profile, evidence and invalidation references are composition-supplied
    /// metadata echoed into the row from `ctx`; the Kernel composition wraps
    /// this row in its own evidence record with the configuration snapshot
    /// and Authority Epoch it resolved.
    ///
    /// The row is checked by the existing
    /// [`BottleneckCapacityProfile::validate`] before it is returned, so a
    /// missing owner, generation, physical total, protected partition,
    /// enforcement, proof, evidence or invalidation reference fails here
    /// rather than publishing a row the Kernel composition would have to lower
    /// to `UNKNOWN`. Missing, duplicate and foreign rows are unrepresentable:
    /// the fixed-size result carries exactly one row and the helper below
    /// builds it only for this owner's own bottleneck, looked up in the
    /// frozen owner map rather than restated here.
    ///
    /// # Errors
    ///
    /// Returns [`NotifyReserveError::Contract`] when the frozen owner map
    /// binds no owner to the notification dimension, when the configured
    /// partition capacities cannot form a positive physical total, or when
    /// the assembled row fails the existing contract validation.
    pub fn publish_owner_rows(
        &self,
        ctx: &NotifyOwnerEvidenceContext,
    ) -> Result<[BottleneckCapacityProfile; 1], NotifyReserveError> {
        let row = notify_owner_capacity_row(
            self.inner.normal_capacity,
            self.inner.protected_capacity,
            ctx,
        )?;
        Ok([row])
    }
}

/// Exact parts of one notification rejection directive shared by every
/// constructor.
struct NotifyRejectionParts {
    affected: AffectedOperationClass,
    observation: BottleneckObservationV1,
    operation_id: Option<OperationId>,
    profile_revision: ArtifactId,
}

impl NotifyRejectionParts {
    /// Assembles the versioned response and validates it with the existing
    /// contract check; an inconsistent observation fails closed here.
    fn into_response(
        self,
        disposition: BackpressureDisposition,
        work_outcome: I14WorkOutcome,
        commit_status: RecoveryCommitStatus,
    ) -> Result<I14BackpressureResponseV1, NotifyReserveError> {
        let response = I14BackpressureResponseV1 {
            contract_version: I14_BACKPRESSURE_RESPONSE_VERSION,
            disposition,
            directive: I14RecoveryDirectiveV1 {
                cause: I14BackpressureCause::CapacityExhaustion,
                affected_operation_class: self.affected,
                bottlenecks: vec![self.observation],
                work_outcome,
                commit_status,
                state_preservation: StatePreservationStatus::Preserved,
                operation_id: self.operation_id,
                preserve_operation_id: true,
                stage_receipt: None,
                rollback_receipt: None,
                retry_strategy: I14RecoveryAction::AwaitCondition,
                earliest_permitted_condition: EarliestRecoveryCondition::CapacityAvailable,
                earliest_permitted_unix_millis: None,
                actions_temporarily_forbidden: Vec::<I14ForbiddenAction>::new(),
                safe_fallback: None,
                required_authority: I14RequiredAuthority::NoneRequired,
                human_action_required: HumanActionRequirement::NoneRequired,
                evidence_refs: Vec::new(),
                evidence_coverage: EvidenceCoverageState::Unavailable,
                escalation_condition: I14EscalationCondition::None,
                resolution_state: I14ResolutionState::Pending,
                currentness: I14CurrentnessState::Current,
                profile_revision: self.profile_revision,
                state_fence: None,
                authority_epoch: None,
            },
        };
        response
            .validate()
            .map_err(|error| NotifyReserveError::Contract(error.to_string()))?;
        Ok(response)
    }
}

/// Builds the claimed owner row for the notification dimension from the
/// reserve's configured partition capacities and the composition-resolved
/// references.
///
/// The owner reference is read from the frozen owner map, never restated here;
/// the unit is the bottleneck's own declared unit. The physical total is
/// exactly the sum of the two disjoint partitions, so the existing partition
/// accounting check always bounds them. A zero partition capacity or a missing
/// frozen owner fails closed: the reserve constructor already refuses zero
/// partitions, and a dimension without a frozen owner has no claim to publish.
fn notify_owner_capacity_row(
    normal_capacity: u64,
    protected_capacity: u64,
    ctx: &NotifyOwnerEvidenceContext,
) -> Result<BottleneckCapacityProfile, NotifyReserveError> {
    let owner = frozen_bottleneck_owner_map()
        .into_iter()
        .find(|bound| bound.bottleneck == NOTIFICATION_INBOX_BOTTLENECK)
        .map(|bound| bound.owner)
        .ok_or_else(|| {
            NotifyReserveError::Contract(format!(
                "frozen owner map binds no owner to {NOTIFICATION_INBOX_BOTTLENECK:?}; no notification row to publish"
            ))
        })?;
    let unit = NOTIFICATION_INBOX_BOTTLENECK.unit();
    let limit = |field: &'static str, amount: u64| {
        NonZeroU64::new(amount)
            .map(|quantity| CapacityLimit { unit, quantity })
            .ok_or(NotifyReserveError::InvalidField {
                field,
                reason: "partition capacity must be greater than zero",
            })
    };
    let normal_limit = limit("notify_reserve.normal_limit", normal_capacity)?;
    let protected_limit = limit("notify_reserve.protected_limit", protected_capacity)?;
    let physical_total =
        normal_capacity
            .checked_add(protected_capacity)
            .ok_or(NotifyReserveError::InvalidField {
                field: "notify_reserve.physical_total_limit",
                reason: "disjoint partition capacities overflow the physical total",
            })?;
    let physical_total_limit =
        NonZeroU64::new(physical_total).ok_or(NotifyReserveError::InvalidField {
            field: "notify_reserve.physical_total_limit",
            reason: "physical total must be greater than zero",
        })?;
    let row = BottleneckCapacityProfile {
        bottleneck: NOTIFICATION_INBOX_BOTTLENECK,
        coverage_state: BottleneckCoverageState::Claimed,
        owner_ref: owner.to_owned(),
        owner_generation_ref: ctx.owner_generation_ref.clone(),
        unit,
        physical_total_limit: Some(CapacityLimit {
            unit,
            quantity: physical_total_limit,
        }),
        normal_work_applicable: true,
        normal_limit: Some(normal_limit),
        protected_limit: Some(protected_limit),
        emergency_limit: None,
        enforcement: Some(CapacityEnforcement::ConfigurationPartition),
        proof_profile_ref: ctx.proof_profile_ref.clone(),
        evidence_refs: ctx.evidence_refs.clone(),
        invalidation_set: ctx.invalidation_set.clone(),
    };
    row.validate()
        .map_err(|error| NotifyReserveError::Contract(error.to_string()))?;
    Ok(row)
}
