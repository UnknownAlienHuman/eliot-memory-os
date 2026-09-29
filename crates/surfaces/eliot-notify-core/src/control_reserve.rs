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
//! This module has no production caller yet (STITCH): it publishes the owner
//! evidence the notification profile composition will join. There is no
//! emergency partition here; recording reserve loss stays with the front-door
//! last-resort slot until a later wave wires notification-side loss
//! reporting.
//! DISCLOSED LIMIT: `profile_revision` on the response is caller-supplied
//! metadata echoed into the directive; the `Current` currentness claim refers
//! to the live-observed saturation at call time, not to a re-read of the
//! profile revision. Full installed-saturation proof stays #11 Product scope.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_contracts::{ArtifactId, OperationId};
use eliot_runtime_contracts::{
    AffectedOperationClass, BackpressureDisposition, BottleneckAvailability,
    BottleneckCoverageState, BottleneckObservationV1, CapacityBottleneck, CapacityClass,
    ControlOperationClass, EarliestRecoveryCondition, EvidenceCoverageState,
    HumanActionRequirement, I14_BACKPRESSURE_RESPONSE_VERSION, I14BackpressureCause,
    I14BackpressureResponseV1, I14CurrentnessState, I14EscalationCondition, I14ForbiddenAction,
    I14RecoveryAction, I14RecoveryDirectiveV1, I14RequiredAuthority, I14ResolutionState,
    I14WorkOutcome, NormalWorkClass, RecoveryCommitStatus, StatePreservationStatus,
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
        "notification normal capacity exhausted for {bottleneck:?}: work {work_class:?} operation {operation_id} owned by {owner}"
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
    },
    /// The protected partition cannot satisfy the request.
    #[error(
        "notification protected reserve exhausted for {bottleneck:?}: control operation {operation:?} operation {operation_id} owned by {owner}"
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

/// One held notification capacity permit, bound to class, operation and
/// owner. Releasing is automatic on drop and returns exactly the consumed
/// partition.
///
/// Permits are deliberately not [`Clone`]: duplicating a permit handle must
/// never duplicate the underlying capacity.
#[derive(Debug)]
pub struct NotifyPermit {
    inner: Arc<NotifyReserveInner>,
    class: CapacityClass,
    operation: NotifyPermitOperation,
    operation_id: String,
    owner: String,
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
    /// construction.
    ///
    /// # Errors
    ///
    /// Returns [`NotifyReserveError::InvalidField`] for a blank
    /// owner/operation identity, or
    /// [`NotifyReserveError::NormalCapacityExhausted`] naming the inbox
    /// bottleneck and shed work when the normal partition is saturated. The
    /// protected partition is untouched in every case.
    pub fn try_acquire_normal_inbox(
        &self,
        work: NormalWorkClass,
        owner: &str,
        operation_id: &str,
    ) -> Result<NotifyPermit, NotifyReserveError> {
        validate_text(owner, "notify_permit.owner")?;
        validate_text(operation_id, "notify_permit.operation_id")?;
        if !cas_add_one(&self.inner.normal_in_flight, self.inner.normal_capacity) {
            return Err(NotifyReserveError::NormalCapacityExhausted {
                bottleneck: NOTIFICATION_INBOX_BOTTLENECK,
                work_class: work,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(NotifyPermit {
            inner: self.inner.clone(),
            class: CapacityClass::NormalWorkload,
            operation: NotifyPermitOperation::Normal(work),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
        })
    }

    /// Attempts to acquire one protected inbox item without blocking.
    ///
    /// Only [`ControlOperationClass`] operations typecheck here: ordinary work
    /// cannot name a protected operation and therefore cannot acquire this
    /// partition. This is the path an admitted cancellation/recovery record
    /// keeps while normal inbox work reports `BUSY`.
    ///
    /// # Errors
    ///
    /// Returns [`NotifyReserveError::InvalidField`] for a blank
    /// owner/operation identity, or
    /// [`NotifyReserveError::ProtectedReserveExhausted`] naming the inbox
    /// bottleneck, operation, owner and request when the protected partition
    /// is saturated.
    pub fn try_acquire_protected_inbox(
        &self,
        operation: ControlOperationClass,
        owner: &str,
        operation_id: &str,
    ) -> Result<NotifyPermit, NotifyReserveError> {
        validate_text(owner, "notify_permit.owner")?;
        validate_text(operation_id, "notify_permit.operation_id")?;
        if !cas_add_one(&self.inner.protected_in_flight, self.inner.protected_capacity) {
            return Err(NotifyReserveError::ProtectedReserveExhausted {
                bottleneck: NOTIFICATION_INBOX_BOTTLENECK,
                operation,
                operation_id: operation_id.to_owned(),
                owner: owner.to_owned(),
            });
        }
        Ok(NotifyPermit {
            inner: self.inner.clone(),
            class: CapacityClass::ProtectedControl,
            operation: NotifyPermitOperation::Protected(operation),
            operation_id: operation_id.to_owned(),
            owner: owner.to_owned(),
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
