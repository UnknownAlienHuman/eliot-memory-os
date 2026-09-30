//! Versioned I14 backpressure and capacity-recovery wire contract.
//!
//! This contract describes an owner-produced observation and next step. It
//! does not acquire capacity, grant authority, or perform recovery.

use eliot_contracts::{
    ArtifactId, ContractIdentity, ContractVersion, EpochId, OperationId, ReceiptId, StateFence,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    BackpressureDisposition, BottleneckCoverageState, CapacityBottleneck, CapacityUnit,
    ControlOperationClass, EmergencyOperationClass, NormalWorkClass, RecoveryCommitStatus,
    RuntimeContractError,
};

/// Wire version for the I14 backpressure response and recovery directive.
pub const I14_BACKPRESSURE_RESPONSE_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Stable identity name for the separate I14 response schema handshake.
pub const I14_BACKPRESSURE_CONTRACT_NAME: &str =
    "eliot.foundation.runtime-contracts.i14-backpressure";
/// Version of the separate I14 response schema identity.
pub const I14_BACKPRESSURE_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// The closed work/operation class affected by a backpressure response.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AffectedOperationClass {
    /// Ordinary workload operation.
    Normal(NormalWorkClass),
    /// Protected control/recovery operation.
    Protected(ControlOperationClass),
    /// Emergency last-resort operation.
    Emergency(EmergencyOperationClass),
}

impl AffectedOperationClass {
    /// Returns the partition selected by the closed operation class.
    #[must_use]
    pub const fn capacity_class(self) -> super::CapacityClass {
        match self {
            Self::Normal(_) => super::CapacityClass::NormalWorkload,
            Self::Protected(_) => super::CapacityClass::ProtectedControl,
            Self::Emergency(_) => super::CapacityClass::EmergencyLastResort,
        }
    }
}

/// Cause categories used by the I14 recovery contract.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum I14BackpressureCause {
    /// One or more exact capacity dimensions cannot satisfy the request.
    CapacityExhaustion,
    /// Canonical state is unavailable for the requested operation.
    CanonicalStoreUnavailable,
    /// The declared work budget is exhausted.
    BudgetExhausted,
    /// A stable packet/read could not be obtained.
    StateChurn,
    /// The requested capability or route is unavailable.
    CapabilityUnavailable,
    /// Work was durably staged and is awaiting completion/readback.
    DurableStagePending,
}

/// Current owner observation for one bottleneck and request quantity.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BottleneckObservationV1 {
    /// Exact bottleneck from the frozen I14 denominator.
    pub bottleneck: CapacityBottleneck,
    /// Exact unit for this bottleneck.
    pub unit: CapacityUnit,
    /// Amount requested in `unit`.
    pub requested_amount: u64,
    /// Current available amount or an explicit unknown/unsupported state.
    pub availability: BottleneckAvailability,
    /// Coverage state from the current owner/profile evidence.
    pub coverage_state: BottleneckCoverageState,
}

/// Observed availability in the unit declared for one bottleneck.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BottleneckAvailability {
    /// Owner observed less available capacity than the request requires.
    Exhausted { available_amount: u64 },
    /// Owner observed enough capacity for the request at this dimension.
    Available { available_amount: u64 },
    /// Current availability could not be established.
    Unknown,
    /// This dimension has no supporting capacity implementation.
    Unsupported,
}

/// State of work or its possible effect for one operation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum I14WorkOutcome {
    /// Work was not accepted for execution.
    NotAccepted,
    /// Work has a durable staged identity awaiting completion/readback.
    Staged,
    /// Work is deferred pending a permitted condition or route.
    Deferred,
    /// Work was shed from the current admission path.
    Shed,
    /// Work was quarantined pending scoped recovery.
    Quarantined,
    /// The effect or work outcome remains unknown.
    Unknown,
}

/// Whether state and operation identity remain available for safe recovery.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StatePreservationStatus {
    /// The operation and required state were preserved.
    Preserved,
    /// Some, but not all, required state was preserved.
    PartiallyPreserved,
    /// Required state was not preserved.
    NotPreserved,
    /// Preservation has not been established.
    Unknown,
}

/// Typed instruction for the next recovery step.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum I14RecoveryAction {
    /// Retry only after a known rollback, preserving the operation identity.
    RetryAfterKnownRollback,
    /// Poll the staged operation by its existing identity.
    PollOperation,
    /// Reconcile the existing operation/effect by receipt or owner readback.
    ReconcileByReceipt,
    /// Wait until the typed earliest-permitted condition is met.
    AwaitCondition,
    /// Stop automatic action and enter manual/platform recovery.
    ManualRecovery,
}

/// Closed condition that permits the next action.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EarliestRecoveryCondition {
    /// No additional wait condition is required.
    NoWaitRequired,
    /// The exact requested capacity is available.
    CapacityAvailable,
    /// A known-rollback receipt is available.
    RollbackReceiptVerified,
    /// Readback/reconciliation evidence is available.
    ReconciliationEvidenceAvailable,
    /// Required authority is restored or revalidated.
    AuthorityRestored,
    /// Human/platform recovery has completed.
    ManualRecoveryComplete,
    /// The next allowed condition/time is unknown.
    Unknown,
}

/// An action the receiver must not take while following this directive.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum I14ForbiddenAction {
    /// Retry an operation while its possible effect remains unresolved.
    BlindRetryAfterPossibleEffect,
    /// Repeat an external effect under a different operation identity.
    DuplicateEffectWithNewIdentity,
    /// Treat a missing receipt/readback as a successful commit.
    AssumeCommitWithoutReadback,
    /// Continue an effect after its authority/fence is stale.
    ContinueWithStaleAuthority,
}

/// A documented alternative route; `None` on the response means no route exists.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum I14AlternativeRoute {
    /// Bounded staging through ORS while canonical storage is unavailable.
    OrsDurableStage,
    /// Continue only with canonical read-only inspection.
    CanonicalReadOnly,
    /// Continue only with noncanonical observation.
    NonCanonicalObservation,
    /// Continue through the separately admitted Human recovery surface.
    HumanRecoverySurface,
    /// Continue through the platform/manual recovery boundary.
    PlatformRecovery,
}

/// Authority requirement; this value declares a requirement and grants none.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum I14RequiredAuthority {
    /// No additional authority is required for the next action.
    NoneRequired,
    /// Revalidate the authority already bound to the operation.
    ExistingOperationAuthority,
    /// A Human decision is required.
    HumanDecision,
    /// Doctor recovery evidence/decision is required.
    DoctorReconciliation,
    /// Human or platform recovery authority is required.
    HumanOrPlatformRecovery,
    /// The required authority has not been established.
    Unknown,
}

/// Whether a Human/Doctor action is explicitly required.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HumanActionRequirement {
    /// No Human/Doctor action is required by this directive.
    NoneRequired,
    /// A Human decision is required.
    HumanDecision,
    /// Doctor reconciliation is required.
    DoctorReconciliation,
    /// Human/platform recovery is required.
    HumanOrPlatformRecovery,
}

/// Evidence/receipt coverage state for this directive.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceCoverageState {
    /// The listed references cover the evidence required by this response.
    Complete,
    /// Some exact references are available; coverage remains partial.
    Partial,
    /// Evidence references are not currently available.
    Unavailable,
    /// Evidence coverage has not been established.
    Unknown,
}

/// Escalation boundary for the affected operation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum I14EscalationCondition {
    /// No escalation condition is currently declared.
    None,
    /// Open or update a scoped Problem State.
    ProblemState,
    /// Open or update an Incident.
    Incident,
    /// Enter the manual/platform recovery boundary.
    ManualPlatformRecovery,
}

/// Current resolution state of the recovery work.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum I14ResolutionState {
    /// Recovery remains unresolved.
    Pending,
    /// Receipt/effect reconciliation is required.
    AwaitingReconciliation,
    /// The exact operation has been resolved.
    Resolved,
    /// Automatic recovery is stopped at a manual boundary.
    ManualRecoveryRequired,
    /// Resolution is unknown.
    Unknown,
}

/// Whether this response still describes the current owner/profile state.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum I14CurrentnessState {
    /// The profile and owner observations are current for this response.
    Current,
    /// The response has been invalidated by a newer relevant state.
    Stale,
    /// Currentness has not been established.
    Unknown,
}

/// Versioned complete I14 recovery directive.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct I14RecoveryDirectiveV1 {
    /// I14 cause category.
    pub cause: I14BackpressureCause,
    /// Closed work/operation class affected by this response.
    pub affected_operation_class: AffectedOperationClass,
    /// One or more exact bottleneck observations; units remain heterogeneous.
    /// Non-capacity causes may report explicit unknown/unsupported observations
    /// because W6 does not claim measured exhaustion for those causes.
    pub bottlenecks: Vec<BottleneckObservationV1>,
    /// Whether work was accepted, staged, deferred, shed, quarantined or unknown.
    pub work_outcome: I14WorkOutcome,
    /// Durable commit status from the existing I14 vocabulary.
    pub commit_status: RecoveryCommitStatus,
    /// Whether state and the operation identity were preserved.
    pub state_preservation: StatePreservationStatus,
    /// Existing operation identity, if one was admitted or created.
    pub operation_id: Option<OperationId>,
    /// Explicitly directs receivers to retain/reuse that operation identity.
    pub preserve_operation_id: bool,
    /// Durable stage receipt; required when `commit_status` is `staged`.
    pub stage_receipt: Option<ReceiptId>,
    /// Receipt/readback proving a known rollback before a same-identity retry.
    pub rollback_receipt: Option<ReceiptId>,
    /// Typed next action.
    pub retry_strategy: I14RecoveryAction,
    /// Earliest condition that permits the next action.
    pub earliest_permitted_condition: EarliestRecoveryCondition,
    /// Optional earliest UTC Unix time in milliseconds, when the owner supplies one.
    pub earliest_permitted_unix_millis: Option<u64>,
    /// Closed actions forbidden while this directive is current.
    pub actions_temporarily_forbidden: Vec<I14ForbiddenAction>,
    /// Exact safe alternative route, or `None` when absent.
    pub safe_fallback: Option<I14AlternativeRoute>,
    /// Authority required to perform the next action; this is not a grant.
    pub required_authority: I14RequiredAuthority,
    /// Explicit Human/Doctor action requirement.
    pub human_action_required: HumanActionRequirement,
    /// Exact durable receipt/evidence handles supporting the directive.
    pub evidence_refs: Vec<ReceiptId>,
    /// Explicit evidence-reference coverage state.
    pub evidence_coverage: EvidenceCoverageState,
    /// Escalation condition when automated recovery cannot proceed.
    /// Unknown commit outcomes must declare a problem, incident, or
    /// manual/platform-recovery boundary (I14.21).
    pub escalation_condition: I14EscalationCondition,
    /// Current recovery resolution state.
    pub resolution_state: I14ResolutionState,
    /// Currentness of the owner/profile observation.
    pub currentness: I14CurrentnessState,
    /// Owner-produced immutable artifact reference for the exact compiled profile revision.
    pub profile_revision: ArtifactId,
    /// State fence binding authority epoch and dependent revisions, when applicable.
    pub state_fence: Option<StateFence>,
    /// Canonical authority epoch when the response is epoch-bound.
    pub authority_epoch: Option<EpochId>,
}

impl I14RecoveryDirectiveV1 {
    /// Validates the complete directive and disposition-dependent safety rules.
    pub fn validate(
        &self,
        disposition: BackpressureDisposition,
    ) -> Result<(), RuntimeContractError> {
        self.validate_bottlenecks(disposition)?;
        self.validate_evidence()?;
        self.validate_disposition_cause_state(disposition)?;
        self.validate_effect_safety()?;
        self.validate_context()?;
        Ok(())
    }

    fn validate_bottlenecks(
        &self,
        disposition: BackpressureDisposition,
    ) -> Result<(), RuntimeContractError> {
        if self.bottlenecks.is_empty() {
            return Err(invalid(
                "bottlenecks",
                "must identify at least one dimension",
            ));
        }

        let mut has_exhausted_dimension = false;
        for (index, observation) in self.bottlenecks.iter().enumerate() {
            if self.bottlenecks[..index]
                .iter()
                .any(|previous| previous.bottleneck == observation.bottleneck)
            {
                return Err(invalid("bottlenecks", "must not repeat a bottleneck"));
            }
            has_exhausted_dimension |= Self::validate_bottleneck_observation(observation)?;
        }

        if matches!(
            disposition,
            BackpressureDisposition::Busy | BackpressureDisposition::StorageBackpressure
        ) && !has_exhausted_dimension
        {
            return Err(invalid(
                "bottlenecks",
                "BUSY and STORAGE_BACKPRESSURE require a claimed, observed exhausted dimension",
            ));
        }
        if disposition == BackpressureDisposition::StorageBackpressure
            && !self.bottlenecks.iter().any(|observation| {
                observation.bottleneck == CapacityBottleneck::OrsDurableQueueBytes
                    && observation.coverage_state == BottleneckCoverageState::Claimed
                    && matches!(
                        observation.availability,
                        BottleneckAvailability::Exhausted { available_amount }
                            if available_amount < observation.requested_amount
                    )
            })
        {
            return Err(invalid(
                "bottlenecks",
                "STORAGE_BACKPRESSURE must name ORS durable queue bytes",
            ));
        }
        Ok(())
    }

    fn validate_bottleneck_observation(
        observation: &BottleneckObservationV1,
    ) -> Result<bool, RuntimeContractError> {
        if observation.requested_amount == 0 {
            return Err(invalid("bottlenecks.requested_amount", "must be positive"));
        }
        if observation.unit != observation.bottleneck.unit() {
            return Err(invalid(
                "bottlenecks.unit",
                "must match the exact bottleneck unit",
            ));
        }
        match (observation.coverage_state, observation.availability) {
            (BottleneckCoverageState::Unsupported, BottleneckAvailability::Unsupported)
            | (
                BottleneckCoverageState::Unknown,
                BottleneckAvailability::Unknown | BottleneckAvailability::Unsupported,
            )
            | (BottleneckCoverageState::Claimed, BottleneckAvailability::Unknown) => {}
            (BottleneckCoverageState::Claimed, BottleneckAvailability::Unsupported) => {
                return Err(invalid(
                    "bottlenecks.availability",
                    "claimed coverage cannot report unsupported availability",
                ));
            }
            (
                BottleneckCoverageState::Claimed,
                BottleneckAvailability::Exhausted { available_amount },
            ) if available_amount < observation.requested_amount => {
                return Ok(true);
            }
            (
                BottleneckCoverageState::Claimed,
                BottleneckAvailability::Available { available_amount },
            ) if available_amount >= observation.requested_amount => {}
            (BottleneckCoverageState::Claimed, BottleneckAvailability::Exhausted { .. }) => {
                return Err(invalid(
                    "bottlenecks.availability",
                    "exhausted availability must be below the requested amount",
                ));
            }
            (BottleneckCoverageState::Claimed, BottleneckAvailability::Available { .. }) => {
                return Err(invalid(
                    "bottlenecks.availability",
                    "available capacity must satisfy the requested amount",
                ));
            }
            (BottleneckCoverageState::Unsupported, _) => {
                return Err(invalid(
                    "bottlenecks.availability",
                    "unsupported coverage must remain unsupported",
                ));
            }
            (BottleneckCoverageState::Unknown, _) => {
                return Err(invalid(
                    "bottlenecks.availability",
                    "unknown coverage must not claim a measured amount",
                ));
            }
        }
        Ok(false)
    }

    fn validate_evidence(&self) -> Result<(), RuntimeContractError> {
        if self
            .evidence_refs
            .iter()
            .enumerate()
            .any(|(index, receipt)| self.evidence_refs[..index].contains(receipt))
        {
            return Err(invalid("evidence_refs", "must not repeat a receipt"));
        }
        if matches!(
            self.evidence_coverage,
            EvidenceCoverageState::Complete | EvidenceCoverageState::Partial
        ) && self.evidence_refs.is_empty()
        {
            return Err(invalid(
                "evidence_refs",
                "complete or partial coverage requires exact receipt references",
            ));
        }
        if let Some(stage_receipt) = &self.stage_receipt {
            if self.commit_status != RecoveryCommitStatus::Staged {
                return Err(invalid(
                    "stage_receipt",
                    "is valid only while commit status is staged",
                ));
            }
            if !self.evidence_refs.contains(stage_receipt) {
                return Err(invalid(
                    "stage_receipt",
                    "must also be included in evidence_refs",
                ));
            }
        }
        if let Some(rollback_receipt) = &self.rollback_receipt {
            if self.retry_strategy != I14RecoveryAction::RetryAfterKnownRollback {
                return Err(invalid(
                    "rollback_receipt",
                    "is valid only for a retry after known rollback",
                ));
            }
            if !self.evidence_refs.contains(rollback_receipt) {
                return Err(invalid(
                    "rollback_receipt",
                    "must also be included in evidence_refs",
                ));
            }
        }
        if self
            .actions_temporarily_forbidden
            .iter()
            .enumerate()
            .any(|(index, action)| self.actions_temporarily_forbidden[..index].contains(action))
        {
            return Err(invalid(
                "actions_temporarily_forbidden",
                "must not repeat an action",
            ));
        }
        Ok(())
    }

    fn validate_disposition_cause_state(
        &self,
        disposition: BackpressureDisposition,
    ) -> Result<(), RuntimeContractError> {
        let expected_cause = match disposition {
            BackpressureDisposition::Busy | BackpressureDisposition::StorageBackpressure => {
                I14BackpressureCause::CapacityExhaustion
            }
            BackpressureDisposition::AcceptedPending => I14BackpressureCause::DurableStagePending,
            BackpressureDisposition::DbUnavailable => {
                I14BackpressureCause::CanonicalStoreUnavailable
            }
            BackpressureDisposition::BudgetExhausted => I14BackpressureCause::BudgetExhausted,
            BackpressureDisposition::StateChurn => I14BackpressureCause::StateChurn,
            BackpressureDisposition::CapabilityDegraded => {
                I14BackpressureCause::CapabilityUnavailable
            }
        };
        if self.cause != expected_cause {
            return Err(invalid(
                "cause",
                "cause must match the selected I14.4 disposition",
            ));
        }
        if matches!(
            disposition,
            BackpressureDisposition::Busy | BackpressureDisposition::StorageBackpressure
        ) && (self.work_outcome != I14WorkOutcome::NotAccepted
            || self.commit_status != RecoveryCommitStatus::None)
        {
            return Err(invalid(
                "work_outcome",
                "BUSY and STORAGE_BACKPRESSURE describe work not accepted for staging",
            ));
        }
        if disposition == BackpressureDisposition::AcceptedPending
            && (self.work_outcome != I14WorkOutcome::Staged
                || self.commit_status != RecoveryCommitStatus::Staged
                || self.stage_receipt.is_none()
                || !matches!(
                    self.retry_strategy,
                    I14RecoveryAction::PollOperation | I14RecoveryAction::ReconcileByReceipt
                ))
        {
            return Err(invalid(
                "disposition",
                "ACCEPTED_PENDING requires durable staged work and poll/reconcile",
            ));
        }
        Ok(())
    }

    fn validate_effect_safety(&self) -> Result<(), RuntimeContractError> {
        self.validate_commit_identity()?;
        self.validate_recovery_action_identity()?;
        self.validate_unknown_effect()?;
        self.validate_retry_safety()?;
        if self.work_outcome == I14WorkOutcome::Unknown
            && self.resolution_state == I14ResolutionState::Resolved
        {
            return Err(invalid(
                "resolution_state",
                "an unknown outcome cannot be reported as resolved",
            ));
        }
        Ok(())
    }

    fn validate_recovery_action_identity(&self) -> Result<(), RuntimeContractError> {
        if matches!(
            self.retry_strategy,
            I14RecoveryAction::PollOperation | I14RecoveryAction::ReconcileByReceipt
        ) && (self.operation_id.is_none() || !self.preserve_operation_id)
        {
            return Err(invalid(
                "operation_id",
                "poll and reconciliation require the existing preserved operation identity",
            ));
        }
        if self.retry_strategy == I14RecoveryAction::ManualRecovery
            && (self.required_authority != I14RequiredAuthority::HumanOrPlatformRecovery
                || self.human_action_required != HumanActionRequirement::HumanOrPlatformRecovery
                || self.escalation_condition != I14EscalationCondition::ManualPlatformRecovery)
        {
            return Err(invalid(
                "retry_strategy",
                "manual recovery requires the human/platform authority and escalation boundary",
            ));
        }
        Ok(())
    }

    fn validate_commit_identity(&self) -> Result<(), RuntimeContractError> {
        let identity_required = matches!(
            self.commit_status,
            RecoveryCommitStatus::Staged
                | RecoveryCommitStatus::Committed
                | RecoveryCommitStatus::Unknown
        );
        if identity_required && (self.operation_id.is_none() || !self.preserve_operation_id) {
            return Err(invalid(
                "operation_id",
                "staged, committed, or unknown outcomes must preserve the exact operation identity",
            ));
        }
        if (self.commit_status == RecoveryCommitStatus::Staged)
            != (self.work_outcome == I14WorkOutcome::Staged)
            || (self.commit_status == RecoveryCommitStatus::Staged && self.stage_receipt.is_none())
        {
            return Err(invalid(
                "commit_status",
                "staged work and commit status must agree and include the durable stage receipt",
            ));
        }
        if self.commit_status == RecoveryCommitStatus::Unknown
            && self.work_outcome != I14WorkOutcome::Unknown
        {
            return Err(invalid(
                "work_outcome",
                "unknown commit status must preserve the unknown outcome",
            ));
        }
        if self.work_outcome == I14WorkOutcome::Unknown
            && self.commit_status != RecoveryCommitStatus::Unknown
        {
            return Err(invalid(
                "commit_status",
                "unknown work/effect outcome must remain an unknown commit status",
            ));
        }
        Ok(())
    }

    fn validate_unknown_effect(&self) -> Result<(), RuntimeContractError> {
        if matches!(
            self.commit_status,
            RecoveryCommitStatus::Staged
                | RecoveryCommitStatus::Committed
                | RecoveryCommitStatus::Unknown
        ) && !self
            .actions_temporarily_forbidden
            .contains(&I14ForbiddenAction::BlindRetryAfterPossibleEffect)
        {
            return Err(invalid(
                "actions_temporarily_forbidden",
                "possible effects must forbid blind retry",
            ));
        }
        if self.commit_status == RecoveryCommitStatus::Unknown
            && !matches!(
                self.retry_strategy,
                I14RecoveryAction::ReconcileByReceipt | I14RecoveryAction::ManualRecovery
            )
        {
            return Err(invalid(
                "retry_strategy",
                "unknown outcomes require receipt reconciliation or manual recovery",
            ));
        }
        if self.commit_status == RecoveryCommitStatus::Unknown
            && ((self.retry_strategy == I14RecoveryAction::ReconcileByReceipt
                && self.earliest_permitted_condition
                    != EarliestRecoveryCondition::ReconciliationEvidenceAvailable)
                || (self.retry_strategy == I14RecoveryAction::ManualRecovery
                    && self.earliest_permitted_condition
                        != EarliestRecoveryCondition::ManualRecoveryComplete))
        {
            return Err(invalid(
                "earliest_permitted_condition",
                "unknown outcomes require reconciliation evidence or completed manual recovery",
            ));
        }
        // I14.21 sends an unknown outcome to a Problem State: the scope pauses,
        // the operation is preserved, and a problem is opened. An unknown
        // commit with no declared escalation boundary would report a possible
        // effect as a warning-only observation, so the directive must name the
        // problem, incident, or manual/platform-recovery boundary that owns
        // the reconciliation.
        if self.commit_status == RecoveryCommitStatus::Unknown
            && self.escalation_condition == I14EscalationCondition::None
        {
            return Err(invalid(
                "escalation_condition",
                "unknown outcomes require a declared problem, incident, or manual-recovery boundary",
            ));
        }
        Ok(())
    }

    fn validate_retry_safety(&self) -> Result<(), RuntimeContractError> {
        if self.retry_strategy == I14RecoveryAction::RetryAfterKnownRollback
            && (self.commit_status != RecoveryCommitStatus::None
                || self.work_outcome != I14WorkOutcome::NotAccepted
                || self.operation_id.is_none()
                || !self.preserve_operation_id
                || self.rollback_receipt.is_none()
                || self.earliest_permitted_condition
                    != EarliestRecoveryCondition::RollbackReceiptVerified)
        {
            return Err(invalid(
                "retry_strategy",
                "retry requires a known non-staged rollback outcome",
            ));
        }
        if self.commit_status == RecoveryCommitStatus::Committed && self.evidence_refs.is_empty() {
            return Err(invalid(
                "evidence_refs",
                "committed status requires an exact receipt reference",
            ));
        }
        Ok(())
    }

    fn validate_context(&self) -> Result<(), RuntimeContractError> {
        if let Some(fence) = &self.state_fence {
            fence.validate()?;
            if self
                .authority_epoch
                .as_ref()
                .is_some_and(|epoch| epoch != &fence.authority_epoch)
            {
                return Err(invalid(
                    "authority_epoch",
                    "must match the epoch bound by state_fence",
                ));
            }
        }
        Ok(())
    }
}

/// Complete versioned public response carrying an I14 disposition and directive.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct I14BackpressureResponseV1 {
    /// Exact version of this response schema.
    pub contract_version: ContractVersion,
    /// One of the seven existing I14.4 dispositions.
    pub disposition: BackpressureDisposition,
    /// Complete recovery instruction for this operation.
    pub directive: I14RecoveryDirectiveV1,
}

impl I14BackpressureResponseV1 {
    /// Validates the response schema version and all recovery invariants.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        if self.contract_version != I14_BACKPRESSURE_RESPONSE_VERSION {
            return Err(invalid(
                "contract_version",
                "does not match I14BackpressureResponseV1",
            ));
        }
        self.directive.validate(self.disposition)
    }
}

fn invalid(field: &'static str, reason: &'static str) -> RuntimeContractError {
    RuntimeContractError::InvalidField { field, reason }
}

/// Returns the independent schema identity for the versioned I14 response.
pub fn i14_backpressure_contract_identity() -> Result<ContractIdentity, RuntimeContractError> {
    eliot_contracts::contract_identity(
        I14_BACKPRESSURE_CONTRACT_NAME,
        I14_BACKPRESSURE_CONTRACT_VERSION,
        &schemars::schema_for!(I14BackpressureResponseV1),
    )
    .map_err(RuntimeContractError::from)
}
