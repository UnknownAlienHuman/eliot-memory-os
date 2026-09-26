//! Post-commit orchestration transition for the authenticated `UserAutomation`
//! operator route, and the concrete runtime adapter over the already-owned Host
//! execution transport.
//!
//! The transition has one parent operation and three distinct phases: the
//! canonical Store commit, the wake publication/cancellation handoff, and the
//! execution disposition. A Store receipt is a configuration fact only; it is
//! never reported as an execution result, and a required handoff that is absent
//! or unknown is never answered as a known success with no recovery directive.
//!
//! The transition also carries the one post-commit orchestration record of that
//! parent operation, so the runtime obligations retained before any owner effect
//! are reported beside the phases they produced.
//!
//! [`UserAutomationOperatorRuntime`] is the concrete
//! [`UserAutomationRuntimePort`](super::UserAutomationRuntimePort) over the
//! already-authenticated `USER_AUTOMATION_RUNTIME_OPERATION` Host channel. It
//! adds no transport, no route, no authority and no second job lifecycle: it
//! only forwards the three port calls to the existing
//! [`UserAutomationHostExecutionClient`] and fails closed where this contour
//! has no owner to reach.

use eliot_contracts::{RequestMetadata, StateFence, sha256_hex};
use eliot_kernel_core::user_automation::{
    AutomationExecutionReference, UserAutomationConfigurationState, UserAutomationDeferReason,
    UserAutomationRevision,
};
use eliot_store_api::{OperationIdentity, WriteReceipt, WriteReceiptStatus};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::user_automation::{
    UserAutomationMutationResult, UserAutomationReadResult, UserAutomationStoreOutcome,
};
use super::user_automation_execution::{
    UserAutomationDurableJobPort, UserAutomationFailurePublication, UserAutomationFailureRecord,
    UserAutomationHorizonTrigger, UserAutomationRuntimeAdmission, UserAutomationRuntimeError,
    UserAutomationRuntimePort, UserAutomationWakeCancellation, UserAutomationWakePort,
    UserAutomationWakeReadRequest, UserAutomationWakeReadback,
};
use super::user_automation_execution_client::{
    UserAutomationHostExecutionClient, UserAutomationHostExecutionTransport,
};
use super::user_automation_orchestration::{
    UserAutomationOrchestrationRecord, UserAutomationRuntimeObligation,
    UserAutomationRuntimeObligationDisposition,
};

/// Stable wire identity of the post-commit orchestration transition.
pub const USER_AUTOMATION_TRANSITION_WIRE_ID: &str = "eliot.kernel.user-automation.transition";
/// Current semantic revision of the post-commit orchestration transition.
pub const USER_AUTOMATION_TRANSITION_WIRE_VERSION: u16 = 1;

/// Canonical Store configuration phase of one parent operation.
///
/// The Store commit is a configuration fact. It is reported here and nowhere
/// else, so an execution or wake handoff can never be inferred from a
/// `WriteReceipt`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UserAutomationConfigurationPhase {
    /// Read-only owner projection; no write receipt exists.
    Read {
        /// Typed read projection returned by the canonical owner.
        result: Box<UserAutomationReadResult>,
    },
    /// Newly committed canonical mutation with its exact receipt.
    Committed {
        /// Canonical Store receipt for this transition.
        receipt: Box<WriteReceipt>,
        /// Typed mutation projection.
        result: Box<UserAutomationMutationResult>,
    },
    /// Exact replay of the same canonical mutation identity.
    ///
    /// A replayed Store mutation resumes and reads the same runtime handoff; it
    /// never re-commits and never mints a second identity.
    Replayed {
        /// Original canonical Store receipt for this transition.
        receipt: Box<WriteReceipt>,
        /// Typed mutation projection.
        result: Box<UserAutomationMutationResult>,
    },
}

impl UserAutomationConfigurationPhase {
    /// Projects one validated canonical Store outcome into its phase.
    #[must_use]
    pub fn from_store_outcome(outcome: UserAutomationStoreOutcome) -> Self {
        match outcome {
            UserAutomationStoreOutcome::Read { result } => Self::Read {
                result: Box::new(result),
            },
            UserAutomationStoreOutcome::Committed { receipt, result } => Self::Committed {
                receipt: Box::new(receipt),
                result: Box::new(result),
            },
            UserAutomationStoreOutcome::Replayed { receipt, result } => Self::Replayed {
                receipt: Box::new(receipt),
                result: Box::new(result),
            },
        }
    }

    /// Returns the typed mutation projection of a committed or replayed change.
    #[must_use]
    pub fn mutation_result(&self) -> Option<&UserAutomationMutationResult> {
        match self {
            Self::Read { .. } => None,
            Self::Committed { result, .. } | Self::Replayed { result, .. } => Some(result),
        }
    }

    /// Returns the typed read projection of a read-only answer.
    #[must_use]
    pub fn read_result(&self) -> Option<&UserAutomationReadResult> {
        match self {
            Self::Read { result } => Some(result),
            Self::Committed { .. } | Self::Replayed { .. } => None,
        }
    }

    /// Reports whether the canonical Store answered with an exact replay.
    #[must_use]
    pub fn replayed(&self) -> bool {
        matches!(self, Self::Replayed { .. })
    }
}

/// Closed disposition of one bounded recurring horizon publication.
///
/// The publication is only `Published` when the schedule owner itself
/// acknowledged every requested occurrence. Every other disposition keeps the
/// exact remaining occurrence set and the replay handle beside a named reason,
/// because "we asked" is not a retained wake and an empty remainder in a failed
/// answer would be indistinguishable from an owner that retained nothing
/// because nothing was ever requested.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UserAutomationHorizonOutcome {
    /// The schedule owner acknowledged every requested occurrence.
    Published {
        /// Owner-issued identity of the publication operation.
        publication_operation_id: Box<eliot_store_api::OperationId>,
    },
    /// The owner acknowledged a strict subset of the requested horizon.
    Partial {
        /// Owner-issued identity of the publication operation.
        publication_operation_id: Box<eliot_store_api::OperationId>,
        /// Closed reason the acknowledgement was partial.
        reason: String,
    },
    /// No schedule owner was reachable; nothing was sent.
    Unavailable {
        /// Closed reason the horizon could not be attempted.
        reason: String,
    },
    /// The owner may have acted and the remainder must be reconciled by
    /// identity before any retry.
    UnknownOutcome {
        /// Closed reason the horizon answer is unresolved.
        reason: String,
    },
}

/// Bounded recurring horizon phase of one parent operation.
///
/// This phase is the projection of a real publication request: the trigger
/// selects the slice, the immutable revision digest binds it to the accepted
/// normalized contract, and `requested_occurrence_ids` /
/// `remaining_occurrence_ids` are the exact sets on each side of the owner
/// answer. The phase publishes no authority: it reports that an owner retained,
/// or did not retain, a wake set.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub struct UserAutomationHorizonPhase {
    /// Closed reason this bounded slice was selected.
    pub trigger: UserAutomationHorizonTrigger,
    /// Stable automation identity the horizon belongs to.
    pub automation_id: String,
    /// Immutable revision identity whose normalized contract was published.
    pub automation_revision: String,
    /// Immutable digest of that revision.
    pub revision_digest: String,
    /// Exact occurrences this request asked the owner to retain.
    pub requested_occurrence_ids: Vec<String>,
    /// Exact occurrences the owner has not acknowledged as retained.
    ///
    /// A failed publication never reports an empty remainder: an empty set there
    /// would claim that nothing is outstanding, which this contour cannot prove.
    pub remaining_occurrence_ids: Vec<String>,
    /// Stable replay handle for the remaining set.
    pub retry_handle: String,
    /// Owner disposition of the request.
    pub outcome: UserAutomationHorizonOutcome,
}

impl UserAutomationHorizonPhase {
    /// Reports whether the schedule owner acknowledged the complete horizon.
    #[must_use]
    pub fn published(&self) -> bool {
        matches!(self.outcome, UserAutomationHorizonOutcome::Published { .. })
            && self.remaining_occurrence_ids.is_empty()
    }
}

/// Wake publication/cancellation phase of the same parent operation.
///
/// A `WakeIntent` grants no authority by itself, so a publication phase here is
/// the owner's own retained record read back over the authenticated channel,
/// and a cancellation phase is the owner's exact cancelled wake identities.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UserAutomationWakePhase {
    /// The operation requires no wake publication or cancellation.
    NotApplicable {
        /// Why no wake handoff belongs to this operation.
        reason: String,
    },
    /// The owner retained the exact wake for the committed occurrence.
    Published {
        /// Exact retained Host wake record for that occurrence.
        readback: UserAutomationWakeReadback,
    },
    /// The owner cancelled exactly these unadmitted wake identities.
    Cancelled {
        /// Exact wake identities the owner reported as cancelled.
        cancelled_wake_ids: Vec<String>,
    },
    /// The owner could not be asked, or its answer was lost.
    ///
    /// An empty target list is never reported here: an owner that cannot
    /// produce a complete exact target list is an unknown answer, not proof
    /// that no wake exists.
    UnknownOutcome {
        /// Closed reason the wake handoff is unresolved.
        reason: String,
    },
    /// No wake owner was reachable for this transition.
    Unavailable {
        /// Closed reason the wake handoff could not be attempted.
        reason: String,
    },
}

impl UserAutomationWakePhase {
    /// Reports whether the owner proved this phase.
    #[must_use]
    pub fn resolved(&self) -> bool {
        matches!(
            self,
            Self::NotApplicable { .. } | Self::Published { .. } | Self::Cancelled { .. }
        )
    }
}
/// Execution disposition phase of the same parent operation.
///
/// The disposition is the deterministic preflight decision plus the existing
/// Durable Job owner's answer. It is never derived from the Store receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UserAutomationExecutionPhase {
    /// The operation requires no execution disposition.
    NotApplicable {
        /// Why no execution handoff belongs to this operation.
        reason: String,
    },
    /// The occurrence was admitted to the existing Durable Job lifecycle.
    Admitted {
        /// Existing Durable Job reference returned by its owner.
        execution: Box<AutomationExecutionReference>,
    },
    /// The occurrence remains unadmitted under an existing owner policy.
    Deferred {
        /// Explicit owner defer reason.
        reason: UserAutomationDeferReason,
    },
    /// Configuration was blocked before any model or provider call.
    BlockedConfig {
        /// Stable revision-bound failure class fingerprint.
        failure_fingerprint: String,
    },
    /// The owner may have acted and the occurrence must be reconciled.
    UnknownOutcome {
        /// Closed reason the execution disposition is unresolved.
        reason: String,
    },
    /// No execution owner was reachable for this transition.
    Unavailable {
        /// Closed reason the execution handoff could not be attempted.
        reason: String,
    },
}

impl UserAutomationExecutionPhase {
    /// Reports whether the owner proved this phase.
    #[must_use]
    pub fn resolved(&self) -> bool {
        matches!(
            self,
            Self::NotApplicable { .. }
                | Self::Admitted { .. }
                | Self::Deferred { .. }
                | Self::BlockedConfig { .. }
        )
    }
}

/// Recovery directive the caller must follow while a handoff phase is
/// unresolved. Its presence is what makes the answer `unknown`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UserAutomationRecoveryPhase {
    /// A required owner is not currently reachable.
    Unavailable {
        /// Closed reason the owner could not be asked.
        reason: String,
    },
    /// A required owner may have acted and must be reconciled by identity.
    UnknownOutcome {
        /// Closed reason the owner answer was lost or indeterminate.
        reason: String,
    },
}

/// One post-commit orchestration transition: the parent operation identity plus
/// the three distinct phases it produced.
///
/// The type makes the honest answer the only expressible one. A resolved
/// execution and wake phase yields no recovery directive; an unresolved one
/// always yields a nameable directive, so the route cannot answer a known
/// success with `recovery: null` while a handoff is absent or unknown.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationOperatorTransition {
    /// Stable wire identity of this transition shape.
    pub wire_id: String,
    /// Semantic revision of this transition shape.
    pub wire_version: u16,
    /// Exact parent operation identity answered by the transition.
    pub identity: OperationIdentity,
    /// Fence under which every phase was observed.
    pub state_fence: StateFence,
    /// Canonical Store configuration phase.
    pub configuration: UserAutomationConfigurationPhase,
    /// Wake publication/cancellation phase.
    pub wake: UserAutomationWakePhase,
    /// Execution disposition phase.
    pub execution: UserAutomationExecutionPhase,
    /// Bounded recurring wake horizon this operation published, when it owns
    /// one. `Create`, a `Resume`, and an `Edit` that committed a new active
    /// revision each own exactly one; every other operation owns none, which is
    /// `None` rather than an empty horizon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub horizon: Option<Box<UserAutomationHorizonPhase>>,
    /// The one post-commit orchestration record of this parent operation, bound
    /// to the runtime obligations that are retained durably before any owner
    /// effect is issued. It is `None` exactly when the operation owns no
    /// runtime obligation, which is a complete answer about an obligation that
    /// never existed rather than an empty record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orchestration: Option<Box<UserAutomationOrchestrationRecord>>,
}

impl UserAutomationOperatorTransition {
    /// Composes the one parent transition from its phases.
    #[must_use]
    pub fn new(
        identity: OperationIdentity,
        state_fence: StateFence,
        configuration: UserAutomationConfigurationPhase,
        wake: UserAutomationWakePhase,
        execution: UserAutomationExecutionPhase,
    ) -> Self {
        Self::with_horizon(
            identity,
            state_fence,
            configuration,
            wake,
            execution,
            None,
            None,
        )
    }

    /// Composes the parent transition with the bounded recurring horizon this
    /// operation published, if it owns one, and the post-commit orchestration
    /// record its runtime obligations were retained under, if it owns any.
    #[must_use]
    pub fn with_horizon(
        identity: OperationIdentity,
        state_fence: StateFence,
        configuration: UserAutomationConfigurationPhase,
        wake: UserAutomationWakePhase,
        execution: UserAutomationExecutionPhase,
        horizon: Option<UserAutomationHorizonPhase>,
        orchestration: Option<UserAutomationOrchestrationRecord>,
    ) -> Self {
        Self {
            wire_id: USER_AUTOMATION_TRANSITION_WIRE_ID.to_owned(),
            wire_version: USER_AUTOMATION_TRANSITION_WIRE_VERSION,
            identity,
            state_fence,
            configuration,
            wake,
            execution,
            horizon: horizon.map(Box::new),
            orchestration: orchestration.map(Box::new),
        }
    }

    /// Returns the recovery directive the caller must follow, if any.
    ///
    /// This is the single source of the route's `status` and `recovery`
    /// members: the answer is `known` exactly when no required handoff phase is
    /// unresolved, so an unknown wake or execution handoff can never be
    /// reported as a known success without recovery.
    #[must_use]
    pub fn recovery(&self) -> Option<UserAutomationRecoveryPhase> {
        match &self.wake {
            UserAutomationWakePhase::UnknownOutcome { reason } => {
                return Some(UserAutomationRecoveryPhase::UnknownOutcome {
                    reason: reason.clone(),
                });
            }
            UserAutomationWakePhase::Unavailable { reason } => {
                return Some(UserAutomationRecoveryPhase::Unavailable {
                    reason: reason.clone(),
                });
            }
            UserAutomationWakePhase::NotApplicable { .. }
            | UserAutomationWakePhase::Published { .. }
            | UserAutomationWakePhase::Cancelled { .. } => {}
        }
        if let Some(horizon) = &self.horizon {
            match &horizon.outcome {
                UserAutomationHorizonOutcome::Published { .. } => {}
                UserAutomationHorizonOutcome::Partial { reason, .. }
                | UserAutomationHorizonOutcome::UnknownOutcome { reason } => {
                    return Some(UserAutomationRecoveryPhase::UnknownOutcome {
                        reason: reason.clone(),
                    });
                }
                UserAutomationHorizonOutcome::Unavailable { reason } => {
                    return Some(UserAutomationRecoveryPhase::Unavailable {
                        reason: reason.clone(),
                    });
                }
            }
        }
        match &self.execution {
            UserAutomationExecutionPhase::UnknownOutcome { reason } => {
                return Some(UserAutomationRecoveryPhase::UnknownOutcome {
                    reason: reason.clone(),
                });
            }
            UserAutomationExecutionPhase::Unavailable { reason } => {
                return Some(UserAutomationRecoveryPhase::Unavailable {
                    reason: reason.clone(),
                });
            }
            UserAutomationExecutionPhase::NotApplicable { .. }
            | UserAutomationExecutionPhase::Admitted { .. }
            | UserAutomationExecutionPhase::Deferred { .. }
            | UserAutomationExecutionPhase::BlockedConfig { .. } => {}
        }
        // The retained obligations are the last source of a directive, so a
        // runtime obligation this operation still owns can never be reported
        // beside a null recovery, and a phase that already named a more
        // specific reason keeps it.
        self.orchestration
            .as_ref()
            .and_then(|record| record.outstanding().into_iter().next())
            .map(recovery_phase_for_obligation)
    }

    /// Reports whether every phase of this transition is owner-proven.
    ///
    /// This is the exact complement of [`Self::recovery`], so the route's
    /// `status` member and its `recovery` directive can never disagree.
    #[must_use]
    pub fn is_known(&self) -> bool {
        self.recovery().is_none()
    }

    /// Rejects a transition whose own projection is not internally honest.
    ///
    /// In particular a cancellation phase may never carry an empty wake list:
    /// the concrete wake owner refuses an empty exact target list before it
    /// reaches the Host journal, so an empty list here could only mean "there
    /// were none", and this check refuses to let that claim through. An owner
    /// that cannot produce a complete exact target list answers unknown instead.
    /// The same rule governs a bounded horizon: an unresolved horizon must
    /// retain the exact remaining occurrence set and a replay handle, because an
    /// empty remainder under a failure answer is indistinguishable from an owner
    /// that retained nothing because nothing was requested.
    pub fn validate(&self) -> Result<(), String> {
        if self.wire_id != USER_AUTOMATION_TRANSITION_WIRE_ID
            || self.wire_version != USER_AUTOMATION_TRANSITION_WIRE_VERSION
        {
            return Err("UserAutomation transition wire identity is not current".to_owned());
        }
        self.identity
            .validate()
            .map_err(|error| error.to_string())?;
        self.state_fence
            .validate()
            .map_err(|error| error.to_string())?;
        self.validate_configuration_receipt_binding()?;
        if let UserAutomationWakePhase::Cancelled { cancelled_wake_ids } = &self.wake {
            if cancelled_wake_ids.is_empty() {
                return Err(
                    "an empty cancelled wake list is not an owner answer for a retirement"
                        .to_owned(),
                );
            }
            let mut unique = BTreeSet::new();
            for wake_id in cancelled_wake_ids {
                if wake_id.trim().is_empty() || !unique.insert(wake_id.as_str()) {
                    return Err("cancelled wake identities must be unique text".to_owned());
                }
            }
        }
        self.validate_horizon_binding()?;
        self.validate_orchestration_binding()?;
        for reason in [
            match &self.wake {
                UserAutomationWakePhase::NotApplicable { reason }
                | UserAutomationWakePhase::UnknownOutcome { reason }
                | UserAutomationWakePhase::Unavailable { reason } => Some(reason.as_str()),
                UserAutomationWakePhase::Published { .. }
                | UserAutomationWakePhase::Cancelled { .. } => None,
            },
            match &self.execution {
                UserAutomationExecutionPhase::NotApplicable { reason }
                | UserAutomationExecutionPhase::UnknownOutcome { reason }
                | UserAutomationExecutionPhase::Unavailable { reason } => Some(reason.as_str()),
                UserAutomationExecutionPhase::Admitted { .. }
                | UserAutomationExecutionPhase::Deferred { .. }
                | UserAutomationExecutionPhase::BlockedConfig { .. } => None,
            },
        ]
        .into_iter()
        .flatten()
        {
            if reason.trim().is_empty() {
                return Err("an unresolved UserAutomation phase needs a named reason".to_owned());
            }
        }
        Ok(())
    }

    fn validate_configuration_receipt_binding(&self) -> Result<(), String> {
        let Some(receipt) = configuration_receipt(&self.configuration) else {
            return Ok(());
        };
        receipt.validate().map_err(|error| error.to_string())?;
        if receipt.status != WriteReceiptStatus::Committed
            || receipt.operation_id != self.identity.operation_id
            || receipt.idempotency_key != self.identity.idempotency_key
            || receipt.canonical_request_hash != self.identity.canonical_request_hash
            || receipt.state_fence != self.state_fence
        {
            return Err(
                "the canonical configuration receipt is not bound to this parent identity and State Fence"
                    .to_owned(),
            );
        }
        Ok(())
    }

    fn validate_horizon_binding(&self) -> Result<(), String> {
        let Some(horizon) = self.horizon.as_deref() else {
            return Ok(());
        };
        validate_horizon_phase(horizon)?;
        // A horizon, including an unresolved one, belongs to the exact
        // immutable revision that this committed mutation produced.
        let revision = committed_revision(&self.configuration)
            .ok_or_else(|| "a horizon phase has no committed configuration revision".to_owned())?;
        if horizon.automation_id != revision.automation_id
            || horizon.automation_revision != revision.revision
            || horizon.revision_digest != revision.digest().map_err(|e| e.to_string())?
        {
            return Err("a horizon phase does not belong to the committed revision".to_owned());
        }
        Ok(())
    }

    fn validate_orchestration_binding(&self) -> Result<(), String> {
        let Some(orchestration) = self.orchestration.as_deref() else {
            return Ok(());
        };
        orchestration
            .validate()
            .map_err(|error| error.to_string())?;
        if orchestration.parent != self.identity || orchestration.state_fence != self.state_fence {
            return Err(
                "a post-commit orchestration record is not bound to this parent operation and \
                 State Fence"
                    .to_owned(),
            );
        }
        let receipt = configuration_receipt(&self.configuration).ok_or_else(|| {
            "a post-commit orchestration record has no canonical configuration receipt".to_owned()
        })?;
        if orchestration.committed_receipt_digest != operator_receipt_evidence_digest(receipt)? {
            return Err(
                "a post-commit orchestration record is not bound to the configuration receipt"
                    .to_owned(),
            );
        }
        let revision = committed_revision(&self.configuration).ok_or_else(|| {
            "a post-commit orchestration record has no committed configuration revision".to_owned()
        })?;
        if orchestration.automation_id != revision.automation_id
            || orchestration.automation_revision != revision.revision
            || orchestration.revision_digest != revision.digest().map_err(|e| e.to_string())?
        {
            return Err(
                "a post-commit orchestration record does not belong to the committed revision"
                    .to_owned(),
            );
        }
        if !orchestration.resolved() && self.recovery().is_none() {
            // The one invariant that makes a retained obligation visible: a
            // runtime obligation this operation still owns, whose owner effect
            // is not durably answered, can never be reported beside a null
            // recovery directive. `recovery` derives its directive from this
            // record, so the two cannot disagree.
            return Err(
                "an unanswered post-commit runtime obligation requires a recovery directive"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

/// Stable schema identity for the public `UserAutomation` operator result.
pub const USER_AUTOMATION_OPERATOR_RESULT_SCHEMA_ID: &str =
    "eliot.kernel.user-automation.operator-result";
/// Current schema revision for the public `UserAutomation` operator result.
pub const USER_AUTOMATION_OPERATOR_RESULT_SCHEMA_VERSION: u16 = 1;

/// Closed status of one versioned `UserAutomation` operator result.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserAutomationOperatorResultStatus {
    /// Every required owner phase is proven by the transition.
    Known,
    /// A required owner phase remains unresolved and requires recovery.
    Unknown,
}

/// Typed payload of one public `UserAutomation` operator result.
#[derive(Clone, Debug, PartialEq, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationOperatorResultValue {
    /// The exact owner transition, including its own wire identity and version.
    pub transition: UserAutomationOperatorTransition,
    /// Bounded schedule occurrence projections for inspection answers.
    pub occurrences: Vec<serde_json::Value>,
}

/// Public, explicitly versioned envelope for one `UserAutomation` operator result.
///
/// The envelope binds the status and recovery directive to the validated owner
/// transition. The transition remains an intact typed value, so its
/// `wire_id`/`wire_version` and optional phase semantics cannot be inferred from
/// a daemon-maintained list of JSON properties.
#[derive(Clone, Debug, PartialEq, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationOperatorResultEnvelope {
    /// Stable identity of this public result shape.
    pub schema_id: String,
    /// Semantic version of this public result shape.
    pub schema_version: u16,
    /// Whether every required owner phase is proven.
    pub status: UserAutomationOperatorResultStatus,
    /// Typed transition and its inspection occurrence projection.
    pub value: UserAutomationOperatorResultValue,
    /// Recovery directive derived from the same transition; serialized as null
    /// exactly when the result status is `known`.
    pub recovery: Option<UserAutomationRecoveryPhase>,
}

impl UserAutomationOperatorResultEnvelope {
    /// Builds the public result from one validated owner transition.
    pub fn new(
        transition: UserAutomationOperatorTransition,
        occurrences: Vec<serde_json::Value>,
    ) -> Result<Self, String> {
        transition.validate()?;
        let recovery = transition.recovery();
        let status = if recovery.is_some() {
            UserAutomationOperatorResultStatus::Unknown
        } else {
            UserAutomationOperatorResultStatus::Known
        };
        let envelope = Self {
            schema_id: USER_AUTOMATION_OPERATOR_RESULT_SCHEMA_ID.to_owned(),
            schema_version: USER_AUTOMATION_OPERATOR_RESULT_SCHEMA_VERSION,
            status,
            value: UserAutomationOperatorResultValue {
                transition,
                occurrences,
            },
            recovery,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Rejects a schema or status/recovery pair inconsistent with its transition.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_id != USER_AUTOMATION_OPERATOR_RESULT_SCHEMA_ID
            || self.schema_version != USER_AUTOMATION_OPERATOR_RESULT_SCHEMA_VERSION
        {
            return Err("UserAutomation operator result schema is not current".to_owned());
        }
        self.value.transition.validate()?;
        let expected_recovery = self.value.transition.recovery();
        let expected_status = if expected_recovery.is_some() {
            UserAutomationOperatorResultStatus::Unknown
        } else {
            UserAutomationOperatorResultStatus::Known
        };
        if self.status != expected_status || self.recovery != expected_recovery {
            return Err(
                "UserAutomation operator result status/recovery does not match its transition"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

/// Returns the receipt carried by a committed or replayed configuration phase.
fn configuration_receipt(phase: &UserAutomationConfigurationPhase) -> Option<&WriteReceipt> {
    match phase {
        UserAutomationConfigurationPhase::Read { .. } => None,
        UserAutomationConfigurationPhase::Committed { receipt, .. }
        | UserAutomationConfigurationPhase::Replayed { receipt, .. } => Some(receipt),
    }
}

/// Returns the revision a committed or replayed configuration mutation produced.
fn committed_revision(phase: &UserAutomationConfigurationPhase) -> Option<&UserAutomationRevision> {
    match phase.mutation_result()? {
        UserAutomationMutationResult::Revision { revision, .. } => Some(revision),
        UserAutomationMutationResult::RunNow { .. } => None,
    }
}

/// Computes the same SHA-256 over `serde_json` receipt bytes as
/// `store_gateway::committed_receipt_digest` and `receipt_evidence_digest`.
fn operator_receipt_evidence_digest(receipt: &WriteReceipt) -> Result<String, String> {
    let bytes = serde_json::to_vec(receipt).map_err(|error| error.to_string())?;
    Ok(sha256_hex(&bytes))
}

/// Recovery directive for one runtime obligation that is not durably answered.
///
/// A `Reconciling` obligation is one whose owner effect may already have been
/// issued, so its directive is the unknown-outcome one: the original owner
/// operation identity must be reconciled before the effect is repeated or
/// released. A `Retained` obligation was never issued and an `Unavailable` one
/// could not be retained at all; both are owed to an owner that is not
/// currently reachable. An answered obligation is never passed here, because the
/// caller only asks for obligations that are not durably answered, and the arm
/// states that fact rather than assuming it.
fn recovery_phase_for_obligation(
    obligation: &UserAutomationRuntimeObligation,
) -> UserAutomationRecoveryPhase {
    match &obligation.disposition {
        UserAutomationRuntimeObligationDisposition::Reconciling { reason } => {
            UserAutomationRecoveryPhase::UnknownOutcome {
                reason: reason.clone(),
            }
        }
        UserAutomationRuntimeObligationDisposition::Retained => {
            UserAutomationRecoveryPhase::Unavailable {
                reason: format!(
                    "runtime obligation {} of kind {} covers {} exact occurrence identities and is \
                     durably retained, but its owner effect has not been issued",
                    obligation.owner_operation_id,
                    obligation.kind.as_str(),
                    obligation.subject_ids.len()
                ),
            }
        }
        UserAutomationRuntimeObligationDisposition::Unavailable { reason } => {
            UserAutomationRecoveryPhase::Unavailable {
                reason: reason.clone(),
            }
        }
        UserAutomationRuntimeObligationDisposition::Answered { .. } => {
            UserAutomationRecoveryPhase::Unavailable {
                reason: format!(
                    "runtime obligation {} is reported without a durable owner answer, which this \
                     outbox never records",
                    obligation.owner_operation_id
                ),
            }
        }
    }
}

/// Rejects a horizon phase whose own projection is not internally honest.
///
/// A published horizon must have acknowledged a non-empty requested set and no
/// remainder; an unresolved horizon must name its reason, carry a non-empty
/// requested set, retain a non-empty exact remainder, and carry a replay handle.
/// Every occurrence identity on both sides must be unique text.
fn validate_horizon_phase(horizon: &UserAutomationHorizonPhase) -> Result<(), String> {
    for (value, field) in [
        (&horizon.automation_id, "horizon.automation_id"),
        (&horizon.automation_revision, "horizon.automation_revision"),
        (&horizon.retry_handle, "horizon.retry_handle"),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(format!("horizon phase needs a non-blank {field}"));
        }
    }
    if horizon.revision_digest.len() != 64
        || !horizon
            .revision_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("horizon phase needs a lowercase revision digest".to_owned());
    }
    let mut unique = BTreeSet::new();
    for occurrence_id in horizon
        .requested_occurrence_ids
        .iter()
        .chain(horizon.remaining_occurrence_ids.iter())
    {
        if occurrence_id.trim().is_empty() || !unique.insert(occurrence_id.as_str()) {
            return Err("horizon occurrence identities must be unique text".to_owned());
        }
    }
    if horizon.requested_occurrence_ids.is_empty() {
        return Err("a horizon phase must name the occurrences it requested".to_owned());
    }
    match &horizon.outcome {
        UserAutomationHorizonOutcome::Published { .. } => {
            if !horizon.remaining_occurrence_ids.is_empty() {
                return Err(
                    "a published horizon cannot retain a remaining occurrence set".to_owned(),
                );
            }
        }
        UserAutomationHorizonOutcome::Partial { reason, .. }
        | UserAutomationHorizonOutcome::Unavailable { reason }
        | UserAutomationHorizonOutcome::UnknownOutcome { reason } => {
            if reason.trim().is_empty() {
                return Err("an unresolved horizon needs a named reason".to_owned());
            }
            if horizon.remaining_occurrence_ids.is_empty() {
                return Err(
                    "an unresolved horizon must retain the exact remaining occurrence set; an \
                     empty set would claim that nothing is outstanding"
                        .to_owned(),
                );
            }
        }
    }
    Ok(())
}

/// Concrete `UserAutomationRuntimePort` over the already-authenticated Host
/// execution channel.
///
/// The adapter owns no mutable state and creates no transport: it forwards the
/// three port calls to the existing [`UserAutomationHostExecutionClient`] bound
/// to the server-authored channel, and it fails closed with a named reason
/// wherever this contour has no owner to reach. It is composed by the
/// authenticated `eliot_user_automation` operator route, so the operator commit
/// and the runtime handoff are one parent operation.
pub struct UserAutomationOperatorRuntime<'a, T> {
    client: &'a UserAutomationHostExecutionClient<T>,
}

impl<'a, T> UserAutomationOperatorRuntime<'a, T> {
    /// Borrows the already-authenticated Host execution client.
    #[must_use]
    pub const fn new(client: &'a UserAutomationHostExecutionClient<T>) -> Self {
        Self { client }
    }
}

impl<T> UserAutomationWakePort for UserAutomationOperatorRuntime<'_, T>
where
    T: UserAutomationHostExecutionTransport,
{
    async fn read_pending_wake(
        &self,
        request: impl Into<Box<UserAutomationWakeReadRequest>>,
    ) -> Result<UserAutomationWakeReadback, UserAutomationRuntimeError> {
        // The client's inherent readback is the durable reconciliation path; the
        // trait default would answer `Unavailable` and hide a retained record.
        self.client.read_pending_wake(request).await
    }

    async fn cancel_pending_wakes(
        &self,
        request: impl Into<Box<UserAutomationWakeCancellation>>,
    ) -> Result<Vec<String>, UserAutomationRuntimeError> {
        UserAutomationWakePort::cancel_pending_wakes(self.client, request).await
    }
}

impl<T> UserAutomationRuntimePort for UserAutomationOperatorRuntime<'_, T>
where
    T: UserAutomationHostExecutionTransport,
{
    async fn admit_occurrence(
        &self,
        request: UserAutomationRuntimeAdmission,
    ) -> Result<AutomationExecutionReference, UserAutomationRuntimeError> {
        request
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let occurrence_id = request
            .invocation
            .occurrence_identity()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        // The concrete Host Durable Job owner admits a complete owner-issued
        // submission. A canonical Store receipt is not one: it carries neither
        // the qualified artifact content reference nor the job admission
        // receipt, and inventing either would fabricate content evidence and
        // authority. The absence is reported, never substituted.
        if request.durable_job.is_none() {
            return Err(UserAutomationRuntimeError::Unavailable(format!(
                "occurrence {occurrence_id} has no owner-issued Durable Job submission material; \
                 the qualified artifact content reference and the job admission receipt are issued \
                 by the Durable Job owner and are not derivable from the canonical Store commit"
            )));
        }
        let execution =
            UserAutomationDurableJobPort::admit_occurrence(self.client, request).await?;
        execution
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        Ok(execution)
    }

    async fn cancel_pending_wakes(
        &self,
        request: UserAutomationWakeCancellation,
    ) -> Result<Vec<String>, UserAutomationRuntimeError> {
        request
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        UserAutomationWakePort::cancel_pending_wakes(self.client, request).await
    }

    async fn deliver_user_automation_failure(
        &self,
        request: UserAutomationFailureRecord,
    ) -> Result<UserAutomationFailurePublication, UserAutomationRuntimeError> {
        request
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        // The canonical failure-history owner and the authenticated B3
        // notification owner are reachable from their own process contours, not
        // from this operator route: `USER_AUTOMATION_RUNTIME_OPERATION` carries
        // no failure-delivery operation. Reporting a publication here would
        // claim a notification that was never sent, so the port refuses with the
        // exact missing owner instead.
        Err(UserAutomationRuntimeError::Unavailable(
            "the canonical failure-history and B3 notification owners are not reachable from the \
             UserAutomation operator route; the blocked occurrence stays unnotified and \
             unreconciled"
                .to_owned(),
        ))
    }
}

/// Builds the wake readback request for one committed `RunNow` occurrence.
///
/// The request reuses the admitted parent identity and reads the occurrence back
/// from the canonical owner, so a replayed Store mutation asks about the same
/// original occurrence instead of minting another manual nonce.
pub fn run_now_wake_read_request(
    context: RequestMetadata,
    authenticated_principal: String,
    identity: OperationIdentity,
    invocation: eliot_kernel_core::user_automation::UserAutomationInvocation,
) -> UserAutomationWakeReadRequest {
    UserAutomationWakeReadRequest {
        context,
        authenticated_principal,
        identity,
        invocation,
    }
}

/// Returns the exact configuration state a committed mutation produced.
///
/// A read-only answer and a `RunNow` answer have no committed configuration
/// state to report.
pub fn committed_configuration_state(
    phase: &UserAutomationConfigurationPhase,
) -> Option<UserAutomationConfigurationState> {
    match phase.mutation_result()? {
        UserAutomationMutationResult::Revision { revision, .. } => {
            Some(revision.configuration_state)
        }
        UserAutomationMutationResult::RunNow { .. } => None,
    }
}
