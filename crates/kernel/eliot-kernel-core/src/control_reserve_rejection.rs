//! Typed front-door saturation reporting as versioned I14 responses (issue #1679).
//!
//! The [`FrontDoor`] already fails closed with typed reserve errors
//! ([`KernelError::NormalCapacityExhausted`],
//! [`KernelError::ProtectedReserveExhausted`] and
//! [`KernelError::ControlGuaranteeLost`]). The methods here render exactly
//! those saturation conditions as versioned I14 backpressure responses
//! ([`I14BackpressureResponseV1`]): normal-partition saturation becomes
//! `BUSY`, protected-partition exhaustion becomes a `BUSY` response carrying
//! the manual/platform-recovery boundary, and a lost last-resort path becomes
//! an explicit `CONTROL_GUARANTEE_LOST` record. Every response is validated by
//! the existing [`I14BackpressureResponseV1::validate`] before it is returned,
//! so an inconsistent observation fails closed instead of emitting a
//! disposition-only or generic queue-full answer.
//!
//! Each method reads the live reserve it reports and refuses to build a
//! response while that reserve still admits work, so pressure evidence is
//! never manufactured. Only reserve saturation is reported: authentication,
//! stale authority, identity-conflict and malformed-input conditions have no
//! constructor here and can never be mis-mapped to backpressure. The Agent
//! Bridge event-correction `RecoveryDirective` and the P07 refusal directive
//! are different namespaces: they cannot typecheck as an argument here, and
//! this module never accepts or emits them.

use eliot_contracts::{ArtifactId, OperationId};
use eliot_runtime_contracts::{
    AffectedOperationClass, BackpressureDisposition, BottleneckAvailability,
    BottleneckCoverageState, BottleneckObservationV1, CapacityBottleneck, ControlOperationClass,
    EarliestRecoveryCondition, EmergencyOperationClass, EvidenceCoverageState,
    HumanActionRequirement, I14_BACKPRESSURE_RESPONSE_VERSION, I14AlternativeRoute,
    I14BackpressureCause, I14BackpressureResponseV1, I14CurrentnessState, I14EscalationCondition,
    I14ForbiddenAction, I14RecoveryAction, I14RecoveryDirectiveV1, I14RequiredAuthority,
    I14ResolutionState, I14WorkOutcome, NormalWorkClass, RecoveryCommitStatus,
    StatePreservationStatus,
};

use crate::error::KernelError;
use crate::module::control_reserve_front_door::{FRONT_DOOR_BOTTLENECK, FrontDoor};

/// Exact parts of one rejection directive shared by every constructor below.
struct RejectionParts {
    affected: AffectedOperationClass,
    observation: BottleneckObservationV1,
    operation_id: Option<OperationId>,
    preserve_operation_id: bool,
    retry_strategy: I14RecoveryAction,
    earliest_condition: EarliestRecoveryCondition,
    forbidden: Vec<I14ForbiddenAction>,
    fallback: Option<I14AlternativeRoute>,
    authority: I14RequiredAuthority,
    human_action: HumanActionRequirement,
    escalation: I14EscalationCondition,
    resolution: I14ResolutionState,
    currentness: I14CurrentnessState,
    preservation: StatePreservationStatus,
    profile_revision: ArtifactId,
}

impl RejectionParts {
    /// Assembles the versioned response and validates it with the existing
    /// contract check; an inconsistent observation fails closed here.
    fn into_response(
        self,
        disposition: BackpressureDisposition,
        cause: I14BackpressureCause,
        work_outcome: I14WorkOutcome,
        commit_status: RecoveryCommitStatus,
    ) -> Result<I14BackpressureResponseV1, KernelError> {
        let response = I14BackpressureResponseV1 {
            contract_version: I14_BACKPRESSURE_RESPONSE_VERSION,
            disposition,
            directive: I14RecoveryDirectiveV1 {
                cause,
                affected_operation_class: self.affected,
                bottlenecks: vec![self.observation],
                work_outcome,
                commit_status,
                state_preservation: self.preservation,
                operation_id: self.operation_id,
                preserve_operation_id: self.preserve_operation_id,
                stage_receipt: None,
                rollback_receipt: None,
                retry_strategy: self.retry_strategy,
                earliest_permitted_condition: self.earliest_condition,
                earliest_permitted_unix_millis: None,
                actions_temporarily_forbidden: self.forbidden,
                safe_fallback: self.fallback,
                required_authority: self.authority,
                human_action_required: self.human_action,
                evidence_refs: Vec::new(),
                evidence_coverage: EvidenceCoverageState::Unavailable,
                escalation_condition: self.escalation,
                resolution_state: self.resolution,
                currentness: self.currentness,
                profile_revision: self.profile_revision,
                state_fence: None,
                authority_epoch: None,
            },
        };
        response.validate()?;
        Ok(response)
    }
}

/// Builds one claimed exhaustion observation in the bottleneck's exact unit.
///
/// # Errors
///
/// Returns [`KernelError::InvalidField`] for a zero request: the contract
/// requires a positive requested amount.
fn exhausted_observation(
    bottleneck: CapacityBottleneck,
    requested_amount: u64,
    available_amount: u64,
) -> Result<BottleneckObservationV1, KernelError> {
    if requested_amount == 0 {
        return Err(KernelError::InvalidField {
            field: "rejection.requested_amount",
            reason: "must be greater than zero",
        });
    }
    Ok(BottleneckObservationV1 {
        bottleneck,
        unit: bottleneck.unit(),
        requested_amount,
        availability: BottleneckAvailability::Exhausted { available_amount },
        coverage_state: BottleneckCoverageState::Claimed,
    })
}

/// Builds one unknown-coverage observation in the bottleneck's exact unit.
///
/// # Errors
///
/// Returns [`KernelError::InvalidField`] for a zero request: the contract
/// requires a positive requested amount.
fn unknown_observation(
    bottleneck: CapacityBottleneck,
    requested_amount: u64,
) -> Result<BottleneckObservationV1, KernelError> {
    if requested_amount == 0 {
        return Err(KernelError::InvalidField {
            field: "rejection.requested_amount",
            reason: "must be greater than zero",
        });
    }
    Ok(BottleneckObservationV1 {
        bottleneck,
        unit: bottleneck.unit(),
        requested_amount,
        availability: BottleneckAvailability::Unknown,
        coverage_state: BottleneckCoverageState::Unknown,
    })
}

impl FrontDoor {
    /// Reports live normal-partition saturation as a `BUSY` response.
    ///
    /// The response is built only while [`FrontDoor::available_normal`] is
    /// zero: pressure evidence is never manufactured for a partition that
    /// still admits work. The observation binds the front-door bottleneck in
    /// its exact unit; protected and emergency availability is not read and
    /// not claimed.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] when the normal partition is
    /// not saturated or the operation identity is malformed, or
    /// [`KernelError::RuntimeContract`] when the assembled directive fails
    /// the existing contract validation.
    pub fn normal_saturation_response(
        &self,
        work: NormalWorkClass,
        operation_id: &str,
        profile_revision: ArtifactId,
    ) -> Result<I14BackpressureResponseV1, KernelError> {
        if self.available_normal() > 0 {
            return Err(KernelError::InvalidField {
                field: "front_door.normal_partition",
                reason: "normal partition is not saturated; no pressure evidence to report",
            });
        }
        let operation = OperationId::new(operation_id).map_err(|_| KernelError::InvalidField {
            field: "rejection.operation_id",
            reason: "must be a bounded non-blank reference",
        })?;
        RejectionParts {
            affected: AffectedOperationClass::Normal(work),
            observation: exhausted_observation(FRONT_DOOR_BOTTLENECK, 1, 0)?,
            operation_id: Some(operation),
            preserve_operation_id: true,
            retry_strategy: I14RecoveryAction::AwaitCondition,
            earliest_condition: EarliestRecoveryCondition::CapacityAvailable,
            forbidden: Vec::new(),
            fallback: None,
            authority: I14RequiredAuthority::NoneRequired,
            human_action: HumanActionRequirement::NoneRequired,
            escalation: I14EscalationCondition::None,
            resolution: I14ResolutionState::Pending,
            currentness: I14CurrentnessState::Current,
            preservation: StatePreservationStatus::Preserved,
            profile_revision,
        }
        .into_response(
            BackpressureDisposition::Busy,
            I14BackpressureCause::CapacityExhaustion,
            I14WorkOutcome::NotAccepted,
            RecoveryCommitStatus::None,
        )
    }

    /// Reports live protected-partition exhaustion as the recovery boundary.
    ///
    /// The response is built only while [`FrontDoor::available_protected`]
    /// is zero. Only the closed [`ControlOperationClass`] family typechecks
    /// here, so ordinary work cannot acquire this directive by relabelling
    /// its priority or class.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] when protected capacity
    /// remains or the operation identity is malformed, or
    /// [`KernelError::RuntimeContract`] when the assembled directive fails
    /// the existing contract validation.
    pub fn protected_exhaustion_response(
        &self,
        operation: ControlOperationClass,
        operation_id: &str,
        profile_revision: ArtifactId,
    ) -> Result<I14BackpressureResponseV1, KernelError> {
        if self.available_protected() > 0 {
            return Err(KernelError::InvalidField {
                field: "front_door.protected_partition",
                reason: "protected capacity remains; no boundary evidence to report",
            });
        }
        let observed = OperationId::new(operation_id).map_err(|_| KernelError::InvalidField {
            field: "rejection.operation_id",
            reason: "must be a bounded non-blank reference",
        })?;
        RejectionParts {
            affected: AffectedOperationClass::Protected(operation),
            observation: exhausted_observation(FRONT_DOOR_BOTTLENECK, 1, 0)?,
            operation_id: Some(observed),
            preserve_operation_id: true,
            retry_strategy: I14RecoveryAction::ManualRecovery,
            earliest_condition: EarliestRecoveryCondition::ManualRecoveryComplete,
            forbidden: Vec::new(),
            fallback: Some(I14AlternativeRoute::HumanRecoverySurface),
            authority: I14RequiredAuthority::HumanOrPlatformRecovery,
            human_action: HumanActionRequirement::HumanOrPlatformRecovery,
            escalation: I14EscalationCondition::ManualPlatformRecovery,
            resolution: I14ResolutionState::ManualRecoveryRequired,
            currentness: I14CurrentnessState::Current,
            preservation: StatePreservationStatus::Preserved,
            profile_revision,
        }
        .into_response(
            BackpressureDisposition::Busy,
            I14BackpressureCause::CapacityExhaustion,
            I14WorkOutcome::NotAccepted,
            RecoveryCommitStatus::None,
        )
    }

    /// Reports a lost last-resort path as an explicit guarantee-loss record.
    ///
    /// The record is built only when both [`FrontDoor::available_emergency`]
    /// and [`FrontDoor::available_protected`] are zero, which is exactly the
    /// condition under which no path remains to record the loss. Only the
    /// closed [`EmergencyOperationClass::ControlGuaranteeLostRecord`]
    /// operation is named; the slot never executes ordinary work.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] when a recording path remains
    /// or the recording identity is malformed, or
    /// [`KernelError::RuntimeContract`] when the assembled directive fails
    /// the existing contract validation.
    pub fn guarantee_lost_response(
        &self,
        recording_operation_id: &str,
        profile_revision: ArtifactId,
    ) -> Result<I14BackpressureResponseV1, KernelError> {
        if self.available_emergency() > 0 || self.available_protected() > 0 {
            return Err(KernelError::InvalidField {
                field: "front_door.last_resort_path",
                reason: "a recording path remains; no guarantee loss to report",
            });
        }
        let operation =
            OperationId::new(recording_operation_id).map_err(|_| KernelError::InvalidField {
                field: "rejection.recording_operation_id",
                reason: "must be a bounded non-blank reference",
            })?;
        RejectionParts {
            affected: AffectedOperationClass::Emergency(
                EmergencyOperationClass::ControlGuaranteeLostRecord,
            ),
            observation: unknown_observation(FRONT_DOOR_BOTTLENECK, 1)?,
            operation_id: Some(operation),
            preserve_operation_id: true,
            retry_strategy: I14RecoveryAction::ManualRecovery,
            earliest_condition: EarliestRecoveryCondition::ManualRecoveryComplete,
            forbidden: vec![I14ForbiddenAction::BlindRetryAfterPossibleEffect],
            fallback: Some(I14AlternativeRoute::HumanRecoverySurface),
            authority: I14RequiredAuthority::HumanOrPlatformRecovery,
            human_action: HumanActionRequirement::HumanOrPlatformRecovery,
            escalation: I14EscalationCondition::ManualPlatformRecovery,
            resolution: I14ResolutionState::ManualRecoveryRequired,
            currentness: I14CurrentnessState::Unknown,
            preservation: StatePreservationStatus::Unknown,
            profile_revision,
        }
        .into_response(
            BackpressureDisposition::CapabilityDegraded,
            I14BackpressureCause::CapabilityUnavailable,
            I14WorkOutcome::Unknown,
            RecoveryCommitStatus::Unknown,
        )
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn genesis_epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::MIN,
        )
        .expect("valid test epoch")
    }

    /// The positive complement of
    /// `normal_saturation_response_refuses_an_unsaturated_partition` in
    /// `crates/kernel/eliot-kernel-core/src/module/control_reserve_front_door.rs`:
    /// that test pins refusal while capacity remains, this one pins a real
    /// `BUSY` report once normal capacity is truly gone, so pressure evidence is
    /// reported only while the partition is live-saturated.
    #[test]
    fn normal_saturation_response_reports_live_saturation_as_busy() -> Result<(), KernelError> {
        let authority = crate::authority::KernelAuthority::new(
            crate::authority::KernelAuthorityKey::from_bytes([17u8; 32]),
            genesis_epoch(),
        );
        let front_door = FrontDoor::partitioned(authority, 1, 1, 8)?;

        // The single normal slot is consumed and held: the permit releases on
        // drop, so the response below observes the live saturated partition.
        let _held =
            front_door.acquire_normal(NormalWorkClass::Interactive, "owner-a", "op-fill-1")?;
        assert_eq!(front_door.available_normal(), 0);

        let response = front_door.normal_saturation_response(
            NormalWorkClass::Interactive,
            "op-report-1",
            eliot_contracts::ArtifactId::new("profile-rev-1").expect("valid artifact id"),
        )?;
        assert!(matches!(
            response.disposition,
            eliot_runtime_contracts::BackpressureDisposition::Busy
        ));
        Ok(())
    }

    /// The positive complement of
    /// `protected_exhaustion_response_refuses_a_remaining_partition` in
    /// `crates/kernel/eliot-kernel-core/src/module/control_reserve_front_door.rs`:
    /// that test pins refusal while protected capacity remains, this one pins a
    /// real recovery-boundary report once the protected partition is truly gone,
    /// so boundary evidence is reported only for live exhaustion.
    #[test]
    fn protected_exhaustion_response_reports_live_boundary() -> Result<(), KernelError> {
        let authority = crate::authority::KernelAuthority::new(
            crate::authority::KernelAuthorityKey::from_bytes([21u8; 32]),
            genesis_epoch(),
        );
        let front_door = FrontDoor::partitioned(authority, 1, 1, 8)?;

        // The single protected slot is consumed and held: the permit releases on
        // drop, so the report below observes the live exhausted partition.
        let _held = front_door.acquire_protected(
            ControlOperationClass::CancelOperation,
            "owner-a",
            "op-fill-1",
        )?;
        assert_eq!(front_door.available_protected(), 0);

        let response = front_door.protected_exhaustion_response(
            ControlOperationClass::CancelOperation,
            "op-report-1",
            eliot_contracts::ArtifactId::new("profile-rev-1").expect("valid artifact id"),
        )?;
        assert!(matches!(
            response.disposition,
            eliot_runtime_contracts::BackpressureDisposition::Busy
        ));
        Ok(())
    }

    /// The positive complement of
    /// `guarantee_lost_response_refuses_a_remaining_last_resort_path` in
    /// `crates/kernel/eliot-kernel-core/src/module/control_reserve_front_door.rs`:
    /// that test pins refusal while a recording path is live, this one pins a
    /// real guarantee-loss record once both the protected partition and the
    /// preallocated last-resort slot are truly gone, so the loss is never
    /// dropped silently.
    #[test]
    fn guarantee_lost_response_records_live_guarantee_loss() -> Result<(), KernelError> {
        let authority = crate::authority::KernelAuthority::new(
            crate::authority::KernelAuthorityKey::from_bytes([23u8; 32]),
            genesis_epoch(),
        );
        let front_door = FrontDoor::partitioned(authority, 1, 1, 8)?;

        // Both recording paths are consumed and held: the permits release on
        // drop, so the record below observes the live guarantee loss.
        let _held_protected = front_door.acquire_protected(
            ControlOperationClass::CancelOperation,
            "owner-a",
            "op-fill-1",
        )?;
        let _held_emergency = front_door.acquire_emergency(
            EmergencyOperationClass::ReserveExhaustionGapRecord,
            "owner-a",
            "op-gap-1",
        )?;
        assert_eq!(front_door.available_protected(), 0);
        assert_eq!(front_door.available_emergency(), 0);

        let response = front_door.guarantee_lost_response(
            "op-loss-1",
            eliot_contracts::ArtifactId::new("profile-rev-1").expect("valid artifact id"),
        )?;
        assert!(matches!(
            response.disposition,
            eliot_runtime_contracts::BackpressureDisposition::CapabilityDegraded
        ));
        Ok(())
    }
}
