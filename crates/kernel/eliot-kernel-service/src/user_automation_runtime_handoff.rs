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
//! only forwards the owner port calls to the existing
//! [`UserAutomationHostExecutionClient`] and fails closed where this contour
//! has no owner to reach.

use eliot_contracts::{RequestMetadata, StateFence};
use eliot_kernel_core::user_automation::{
    AutomationExecutionReference, AutomationOccurrenceIdentity, DstFoldPolicy, DstGapPolicy,
    ScheduleKind, UserAutomationConfigurationState, UserAutomationDeferReason,
    UserAutomationTrigger,
};
use eliot_runtime_contracts::WakeIntentState;
use eliot_store_api::{OperationIdentity, WriteReceipt, WriteReceiptStatus};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::user_automation::{
    UserAutomationMutationResult, UserAutomationReadResult, UserAutomationServiceRequest,
    UserAutomationStoreOutcome,
};
use super::user_automation_execution::{
    UserAutomationAuthenticatedWakeCancellationReadback, UserAutomationDurableJobMaterial,
    UserAutomationDurableJobPort, UserAutomationFailurePublication, UserAutomationFailureRecord,
    UserAutomationHorizonTrigger, UserAutomationRuntimeAdmission, UserAutomationRuntimeError,
    UserAutomationRuntimePort, UserAutomationWakeCancellation,
    UserAutomationWakeEnumerationReceipt, UserAutomationWakeEnumerationRequest,
    UserAutomationWakeHorizonPublication, UserAutomationWakePort, UserAutomationWakePublication,
    UserAutomationWakeReadRequest, UserAutomationWakeReadback,
};
use super::user_automation_execution_client::{
    UserAutomationHostExecutionClient, UserAutomationHostExecutionObserver,
    UserAutomationHostExecutionTransport,
};
use super::user_automation_orchestration::{
    UserAutomationOrchestrationRecord, UserAutomationRuntimeObligation,
    UserAutomationRuntimeObligationDisposition,
};

/// Stable wire identity of the post-commit orchestration transition.
pub const USER_AUTOMATION_TRANSITION_WIRE_ID: &str = "eliot.kernel.user-automation.transition";
/// Current semantic revision of the post-commit orchestration transition.
pub const USER_AUTOMATION_TRANSITION_WIRE_VERSION: u16 = 1;

/// Stable public identity of one Operator result envelope.
pub const USER_AUTOMATION_RESULT_WIRE_ID: &str = "eliot.kernel.user-automation.operator-result";
/// Current version of the result envelope and its closed payload union.
pub const USER_AUTOMATION_RESULT_WIRE_VERSION: u16 = 1;

/// The submitted operation correlation echoed beside every `UserAutomation`
/// result. This is distinct from the JSON-RPC transport identifier, which the
/// current Operator client does not expose.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationResultCorrelation {
    /// Semantic operation identity derived from the submitted idempotency key.
    pub operation_id: String,
    /// Exact retry key present in the submitted Operator request.
    pub idempotency_key: String,
}

/// Disposition of a versioned `UserAutomation` Operator result.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserAutomationOperatorResultStatus {
    /// Every required owner phase is settled.
    Known,
    /// At least one owner phase needs reconciliation or is unavailable.
    Unknown,
}

/// Recovery obligation in the public result envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UserAutomationOperatorResultRecovery {
    /// A required owner is not currently reachable.
    Unavailable { reason: String },
    /// A required owner may have acted and must be reconciled.
    UnknownOutcome { reason: String },
    /// Commit is proven; only the ledger readback remains owed.
    LedgerReadOwed { reason: String },
}

/// Result value committed to one operation and one current State Fence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(untagged)]
pub enum UserAutomationOperatorResultValue {
    /// Full canonical transition plus its deterministic inspection projection.
    Transition(Box<UserAutomationOperatorTransitionValue>),
    /// Typed refusal before the canonical Store was called.
    AttemptRefusal(Box<UserAutomationAttemptRefusalValue>),
    /// Proven absence in an owner readback.
    NotRetained(UserAutomationNotRetainedValue),
    /// The owner could not be reached.
    Unavailable(UserAutomationUnavailableValue),
    /// The owner answer may have been lost after an effect.
    UnknownOutcome(UserAutomationUnknownOutcomeValue),
    /// A commit is proven while a separate ledger read remains owed.
    OutcomeSettled(UserAutomationOutcomeSettledValue),
    /// The owner refused the attempt before Store.
    Rejected(UserAutomationRejectedValue),
    /// The operation or current fence did not match the authenticated request.
    IdentityConflict(UserAutomationIdentityConflictValue),
}

impl<'de> Deserialize<'de> for UserAutomationOperatorResultValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let value = serde_json::Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| D::Error::custom("UserAutomation result value is not an object"))?;
        if object.get("kind").and_then(serde_json::Value::as_str) == Some("user_automation_refusal")
        {
            return serde_json::from_value(value)
                .map(Self::AttemptRefusal)
                .map_err(D::Error::custom);
        }

        let variant = match object.get("outcome").and_then(serde_json::Value::as_str) {
            Some("not_retained") => "not_retained",
            Some("unavailable") => "unavailable",
            Some("unknown_outcome") => "unknown_outcome",
            Some("outcome_settled") => "outcome_settled",
            Some("rejected") => "rejected",
            Some("identity_conflict") => "identity_conflict",
            _ if object.contains_key("transition") => "transition",
            _ => {
                return Err(D::Error::custom(
                    "UserAutomation result value has no supported discriminator",
                ));
            }
        };

        match variant {
            "transition" => serde_json::from_value(value)
                .map(Box::new)
                .map(Self::Transition)
                .map_err(D::Error::custom),
            "not_retained" => serde_json::from_value(value)
                .map(Self::NotRetained)
                .map_err(D::Error::custom),
            "unavailable" => serde_json::from_value(value)
                .map(Self::Unavailable)
                .map_err(D::Error::custom),
            "unknown_outcome" => serde_json::from_value(value)
                .map(Self::UnknownOutcome)
                .map_err(D::Error::custom),
            "outcome_settled" => serde_json::from_value(value)
                .map(Self::OutcomeSettled)
                .map_err(D::Error::custom),
            "rejected" => serde_json::from_value(value)
                .map(Self::Rejected)
                .map_err(D::Error::custom),
            "identity_conflict" => serde_json::from_value(value)
                .map(Self::IdentityConflict)
                .map_err(D::Error::custom),
            _ => Err(D::Error::custom(
                "UserAutomation result value is unsupported",
            )),
        }
    }
}

/// Versioned transition payload. The nested transition retains its own wire
/// identity/version; the result envelope commits the projection and recovery
/// fields around it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationOperatorTransitionValue {
    /// Closed typed transition including its own wire identity and version.
    pub transition: UserAutomationOperatorTransition,
    /// Deterministic read projection paired with the exact transition.
    pub occurrences: Vec<UserAutomationScheduleInspectionProjection>,
}

/// Bounded, typed schedule projection emitted only for the revisions returned
/// by this read transition. Its fields are inspection data; they carry no
/// normalization receipt or provenance claim.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationScheduleInspectionProjection {
    pub automation_id: String,
    pub revision: String,
    pub kind: ScheduleKind,
    pub expression: String,
    pub calendar: String,
    pub timezone: String,
    pub dst_fold: DstFoldPolicy,
    pub dst_gap: DstGapPolicy,
    pub start_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_at: Option<String>,
    pub next_occurrences: Vec<String>,
    pub configuration_state: UserAutomationConfigurationState,
    pub occurrences: Vec<UserAutomationOccurrenceInspectionProjection>,
}

/// One compiled occurrence and the deterministic successor resolved by the
/// same immutable revision compiler.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationOccurrenceInspectionProjection {
    pub identity: AutomationOccurrenceIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_occurrence: Option<String>,
}

/// Owner-authored pre-Store refusal with the original request correlation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationAttemptRefusalValue {
    pub kind: String,
    pub schema_version: u16,
    pub operation: UserAutomationAttemptOperationIdentity,
    pub state_fence: StateFence,
    pub attempt_state: String,
    pub refusal: UserAutomationRefusalDetails,
}

/// Operation identity carried by an attempt refusal.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationAttemptOperationIdentity {
    pub operation_id: String,
    pub request_id: String,
    pub idempotency_key: String,
}

/// Closed semantic details of a typed pre-Store refusal.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationRefusalDetails {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset_seconds: Option<i32>,
}

/// Closed outcome value for a proven negative owner readback.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationNotRetainedValue {
    pub accepted: bool,
    pub outcome: String,
    pub reason: String,
}

/// Closed outcome value for an unavailable owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationUnavailableValue {
    pub outcome: String,
}

/// Closed outcome value for an uncertain owner answer.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationUnknownOutcomeValue {
    pub outcome: String,
}

/// Closed outcome value for a proven commit with a remaining ledger read.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationOutcomeSettledValue {
    pub accepted: bool,
    pub outcome: String,
    pub reason: String,
}

/// Closed outcome value for a pre-Store rejection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationRejectedValue {
    pub accepted: bool,
    pub outcome: String,
    pub reason: String,
}

/// Closed outcome value for an operation/fence conflict.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationIdentityConflictValue {
    pub accepted: bool,
    pub outcome: String,
}

/// Public versioned result envelope shared by known, unknown, and refusal
/// outcomes. The payload union is closed and every envelope echoes the exact
/// request correlation and authenticated current State Fence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationOperatorResultEnvelope {
    /// Closed public result wire identity.
    pub wire_id: String,
    /// Version of the closed public result contract.
    pub wire_version: u16,
    /// Known or unresolved disposition of the whole result.
    pub status: UserAutomationOperatorResultStatus,
    /// Exact semantic identity of the submitted Operator request.
    pub correlation: UserAutomationResultCorrelation,
    /// Authenticated State Fence observed by the Kernel owner.
    pub state_fence: StateFence,
    /// Closed result payload bound to this correlation and fence.
    pub value: UserAutomationOperatorResultValue,
    /// Required owner reconciliation, or absence once settled.
    pub recovery: Option<UserAutomationOperatorResultRecovery>,
}

impl UserAutomationOperatorResultEnvelope {
    /// Binds a transition and inspection projection to the exact submitted
    /// operation and its authenticated current fence before serialization.
    pub fn from_transition(
        request: &UserAutomationServiceRequest,
        transition: UserAutomationOperatorTransition,
    ) -> Result<Self, String> {
        transition.validate_for_request(request)?;
        let occurrences = user_automation_inspection_occurrences(&transition)?;
        validate_schedule_inspection_projections(&transition, &occurrences)?;
        let recovery = transition.recovery().map(result_recovery_from_phase);
        let status = if recovery.is_none() {
            UserAutomationOperatorResultStatus::Known
        } else {
            UserAutomationOperatorResultStatus::Unknown
        };
        let envelope = Self {
            wire_id: USER_AUTOMATION_RESULT_WIRE_ID.to_owned(),
            wire_version: USER_AUTOMATION_RESULT_WIRE_VERSION,
            status,
            correlation: result_correlation(request),
            state_fence: request.context.state_fence.clone(),
            value: UserAutomationOperatorResultValue::Transition(Box::new(
                UserAutomationOperatorTransitionValue {
                    transition,
                    occurrences,
                },
            )),
            recovery,
        };
        envelope.validate_for_request(request)?;
        Ok(envelope)
    }

    /// Converts one legacy internal error projection into the same closed,
    /// versioned public envelope. Legacy JSON never crosses this boundary.
    pub fn bind_internal_response(
        request: &UserAutomationServiceRequest,
        response: &serde_json::Value,
    ) -> Result<Self, String> {
        let object = response
            .as_object()
            .ok_or_else(|| "internal UserAutomation response is not an object".to_owned())?;
        if object.len() != 3
            || !object.contains_key("status")
            || !object.contains_key("value")
            || !object.contains_key("recovery")
        {
            return Err("internal UserAutomation response has an unsupported shape".to_owned());
        }
        let status = match object.get("status").and_then(serde_json::Value::as_str) {
            Some("known") => UserAutomationOperatorResultStatus::Known,
            Some("unknown") => UserAutomationOperatorResultStatus::Unknown,
            _ => return Err("internal UserAutomation response status is unsupported".to_owned()),
        };
        let value = parse_result_value(
            object
                .get("value")
                .cloned()
                .ok_or_else(|| "internal UserAutomation response has no value".to_owned())?,
        )?;
        let recovery = if object
            .get("recovery")
            .is_some_and(serde_json::Value::is_null)
        {
            None
        } else {
            Some(
                serde_json::from_value(object.get("recovery").cloned().ok_or_else(|| {
                    "internal UserAutomation response has no recovery".to_owned()
                })?)
                .map_err(|_| {
                    "internal UserAutomation recovery is not a closed variant".to_owned()
                })?,
            )
        };
        let envelope = Self {
            wire_id: USER_AUTOMATION_RESULT_WIRE_ID.to_owned(),
            wire_version: USER_AUTOMATION_RESULT_WIRE_VERSION,
            status,
            correlation: result_correlation(request),
            state_fence: request.context.state_fence.clone(),
            value,
            recovery,
        };
        envelope.validate_for_request(request)?;
        Ok(envelope)
    }

    /// Validates the complete envelope against the request the authenticated
    /// route actually admitted. This is the only constructor-independent gate.
    #[expect(
        clippy::too_many_lines,
        reason = "closed result variants each require an exact disposition check"
    )]
    pub fn validate_for_request(
        &self,
        request: &UserAutomationServiceRequest,
    ) -> Result<(), String> {
        if self.wire_id != USER_AUTOMATION_RESULT_WIRE_ID
            || self.wire_version != USER_AUTOMATION_RESULT_WIRE_VERSION
            || self.correlation != result_correlation(request)
            || self.state_fence != request.context.state_fence
        {
            return Err(
                "UserAutomation result envelope is not bound to the submitted operation and fence"
                    .to_owned(),
            );
        }
        self.state_fence
            .validate()
            .map_err(|error| error.to_string())?;
        match &self.value {
            UserAutomationOperatorResultValue::Transition(value) => {
                value.transition.validate_for_request(request)?;
                validate_schedule_inspection_projections(&value.transition, &value.occurrences)?;
                if self.recovery.as_ref().is_some_and(|recovery| {
                    matches!(
                        recovery,
                        UserAutomationOperatorResultRecovery::LedgerReadOwed { .. }
                    )
                }) {
                    return Err("transition cannot carry a non-transition recovery kind".to_owned());
                }
                if value.transition.state_fence != self.state_fence
                    || self.recovery.as_ref().and_then(recovery_to_phase)
                        != value.transition.recovery()
                    || self.status
                        != if self.recovery.is_none() {
                            UserAutomationOperatorResultStatus::Known
                        } else {
                            UserAutomationOperatorResultStatus::Unknown
                        }
                {
                    return Err(
                        "UserAutomation transition status/recovery does not join its phases"
                            .to_owned(),
                    );
                }
            }
            UserAutomationOperatorResultValue::AttemptRefusal(value) => {
                if self.status != UserAutomationOperatorResultStatus::Unknown
                    || !self.recovery.as_ref().is_some_and(|recovery| {
                        matches!(
                            recovery,
                            UserAutomationOperatorResultRecovery::UnknownOutcome { .. }
                        )
                    })
                    || value.kind != "user_automation_refusal"
                    || value.schema_version != 1
                    || value.operation.operation_id != self.correlation.operation_id
                    || value.operation.request_id != request.context.request_id.to_string()
                    || value.operation.idempotency_key != self.correlation.idempotency_key
                    || value.state_fence != self.state_fence
                    || value.attempt_state != "store_not_called"
                    || value.refusal.code.trim().is_empty()
                {
                    return Err(
                        "UserAutomation refusal is not bound to the current attempt".to_owned()
                    );
                }
            }
            UserAutomationOperatorResultValue::NotRetained(value) => {
                if self.status != UserAutomationOperatorResultStatus::Known
                    || self.recovery.is_some()
                    || value.accepted
                    || value.outcome != "not_retained"
                    || value.reason.trim().is_empty()
                {
                    return Err(
                        "UserAutomation not-retained result has an invalid disposition".to_owned(),
                    );
                }
            }
            UserAutomationOperatorResultValue::Unavailable(value) => {
                if self.status != UserAutomationOperatorResultStatus::Unknown
                    || !self.recovery.as_ref().is_some_and(|recovery| {
                        matches!(
                            recovery,
                            UserAutomationOperatorResultRecovery::Unavailable { .. }
                        )
                    })
                    || value.outcome != "unavailable"
                {
                    return Err(
                        "UserAutomation unavailable result has an invalid disposition".to_owned(),
                    );
                }
            }
            UserAutomationOperatorResultValue::UnknownOutcome(value) => {
                if self.status != UserAutomationOperatorResultStatus::Unknown
                    || !self.recovery.as_ref().is_some_and(|recovery| {
                        matches!(
                            recovery,
                            UserAutomationOperatorResultRecovery::UnknownOutcome { .. }
                        )
                    })
                    || value.outcome != "unknown_outcome"
                {
                    return Err(
                        "UserAutomation unknown result has an invalid disposition".to_owned()
                    );
                }
            }
            UserAutomationOperatorResultValue::OutcomeSettled(value) => {
                if self.status != UserAutomationOperatorResultStatus::Known
                    || !self.recovery.as_ref().is_some_and(|recovery| {
                        matches!(
                            recovery,
                            UserAutomationOperatorResultRecovery::LedgerReadOwed { .. }
                        )
                    })
                    || !value.accepted
                    || value.outcome != "outcome_settled"
                    || value.reason.trim().is_empty()
                {
                    return Err(
                        "UserAutomation settled result has an invalid disposition".to_owned()
                    );
                }
            }
            UserAutomationOperatorResultValue::Rejected(value) => {
                if self.status != UserAutomationOperatorResultStatus::Known
                    || self.recovery.is_some()
                    || value.accepted
                    || value.outcome != "rejected"
                    || value.reason.trim().is_empty()
                {
                    return Err(
                        "UserAutomation rejection result has an invalid disposition".to_owned()
                    );
                }
            }
            UserAutomationOperatorResultValue::IdentityConflict(value) => {
                if self.status != UserAutomationOperatorResultStatus::Known
                    || self.recovery.is_some()
                    || value.accepted
                    || value.outcome != "identity_conflict"
                {
                    return Err(
                        "UserAutomation identity conflict has an invalid disposition".to_owned(),
                    );
                }
            }
        }
        Ok(())
    }
}

fn user_automation_inspection_occurrences(
    transition: &UserAutomationOperatorTransition,
) -> Result<Vec<UserAutomationScheduleInspectionProjection>, String> {
    let UserAutomationConfigurationPhase::Read { result } = &transition.configuration else {
        return Ok(Vec::new());
    };
    let revisions: Vec<&eliot_kernel_core::UserAutomationRevision> = match result.as_ref() {
        UserAutomationReadResult::List { revisions } => revisions.iter().collect(),
        UserAutomationReadResult::Status { revision, .. }
        | UserAutomationReadResult::InspectLastFailure { revision, .. } => vec![revision],
        UserAutomationReadResult::History { .. } => Vec::new(),
    };
    let mut projections = Vec::with_capacity(revisions.len());
    for revision in revisions {
        revision.validate().map_err(|error| error.to_string())?;
        let identities = revision
            .compile_occurrence_identities()
            .map_err(|error| error.to_string())?;
        let mut occurrences = Vec::with_capacity(identities.len());
        for identity in identities {
            let occurrence_key = match &identity.trigger {
                UserAutomationTrigger::Scheduled { occurrence_key } => occurrence_key.as_str(),
                UserAutomationTrigger::Manual { .. } => {
                    return Err(
                        "compiled UserAutomation schedule identity is unexpectedly manual"
                            .to_owned(),
                    );
                }
            };
            let next_occurrence = revision
                .next_occurrence_after(occurrence_key)
                .map_err(|error| error.to_string())?;
            occurrences.push(UserAutomationOccurrenceInspectionProjection {
                identity,
                next_occurrence,
            });
        }
        projections.push(UserAutomationScheduleInspectionProjection {
            automation_id: revision.automation_id.clone(),
            revision: revision.revision.clone(),
            kind: revision.schedule.kind,
            expression: revision.schedule.expression.clone(),
            calendar: revision.schedule.calendar.clone(),
            timezone: revision.schedule.timezone.clone(),
            dst_fold: revision.schedule.dst_fold,
            dst_gap: revision.schedule.dst_gap,
            start_at: revision.schedule.start_at.clone(),
            end_at: revision.schedule.end_at.clone(),
            next_occurrences: revision.schedule.next_occurrences.clone(),
            configuration_state: revision.configuration_state,
            occurrences,
        });
    }
    Ok(projections)
}

fn validate_schedule_inspection_projections(
    transition: &UserAutomationOperatorTransition,
    projections: &[UserAutomationScheduleInspectionProjection],
) -> Result<(), String> {
    let expected = user_automation_inspection_occurrences(transition)?;
    if projections != expected {
        return Err(
            "UserAutomation schedule projection does not exactly match its owner transition"
                .to_owned(),
        );
    }
    Ok(())
}

fn result_correlation(request: &UserAutomationServiceRequest) -> UserAutomationResultCorrelation {
    UserAutomationResultCorrelation {
        operation_id: request.identity.operation_id.to_string(),
        idempotency_key: request.identity.idempotency_key.clone(),
    }
}

fn parse_result_value(
    value: serde_json::Value,
) -> Result<UserAutomationOperatorResultValue, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "UserAutomation result value is not an object".to_owned())?;
    if object.contains_key("transition") {
        return serde_json::from_value(value)
            .map(UserAutomationOperatorResultValue::Transition)
            .map_err(|_| "UserAutomation transition result is not closed".to_owned());
    }
    if object.get("kind").and_then(serde_json::Value::as_str) == Some("user_automation_refusal") {
        return serde_json::from_value(value)
            .map(|value| UserAutomationOperatorResultValue::AttemptRefusal(Box::new(value)))
            .map_err(|_| "UserAutomation attempt refusal is not closed".to_owned());
    }
    let outcome = object
        .get("outcome")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "UserAutomation outcome value has no closed discriminator".to_owned())?;
    match outcome {
        "not_retained" => serde_json::from_value(value)
            .map(UserAutomationOperatorResultValue::NotRetained)
            .map_err(|_| "UserAutomation not-retained value is not closed".to_owned()),
        "unavailable" => serde_json::from_value(value)
            .map(UserAutomationOperatorResultValue::Unavailable)
            .map_err(|_| "UserAutomation unavailable value is not closed".to_owned()),
        "unknown_outcome" => serde_json::from_value(value)
            .map(UserAutomationOperatorResultValue::UnknownOutcome)
            .map_err(|_| "UserAutomation unknown value is not closed".to_owned()),
        "outcome_settled" => serde_json::from_value(value)
            .map(UserAutomationOperatorResultValue::OutcomeSettled)
            .map_err(|_| "UserAutomation settled value is not closed".to_owned()),
        "rejected" => serde_json::from_value(value)
            .map(UserAutomationOperatorResultValue::Rejected)
            .map_err(|_| "UserAutomation rejection value is not closed".to_owned()),
        "identity_conflict" => serde_json::from_value(value)
            .map(UserAutomationOperatorResultValue::IdentityConflict)
            .map_err(|_| "UserAutomation identity conflict value is not closed".to_owned()),
        _ => Err("UserAutomation result outcome is unsupported".to_owned()),
    }
}

fn result_recovery_from_phase(
    recovery: UserAutomationRecoveryPhase,
) -> UserAutomationOperatorResultRecovery {
    match recovery {
        UserAutomationRecoveryPhase::Unavailable { reason } => {
            UserAutomationOperatorResultRecovery::Unavailable { reason }
        }
        UserAutomationRecoveryPhase::UnknownOutcome { reason } => {
            UserAutomationOperatorResultRecovery::UnknownOutcome { reason }
        }
    }
}

fn recovery_to_phase(
    recovery: &UserAutomationOperatorResultRecovery,
) -> Option<UserAutomationRecoveryPhase> {
    match recovery {
        UserAutomationOperatorResultRecovery::Unavailable { reason } => {
            Some(UserAutomationRecoveryPhase::Unavailable {
                reason: reason.clone(),
            })
        }
        UserAutomationOperatorResultRecovery::UnknownOutcome { reason } => {
            Some(UserAutomationRecoveryPhase::UnknownOutcome {
                reason: reason.clone(),
            })
        }
        UserAutomationOperatorResultRecovery::LedgerReadOwed { .. } => None,
    }
}

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
        if let Some(horizon) = &self.horizon {
            validate_horizon_phase(horizon)?;
            if horizon.published() {
                // A published horizon is an owner-acknowledged wake set, never a
                // configuration fact: the transition may only report one beside
                // a committed revision of the same immutable identity.
                if committed_revision_id(&self.configuration).as_deref()
                    != Some(horizon.automation_revision.as_str())
                {
                    return Err(
                        "a published horizon does not belong to the committed revision".to_owned(),
                    );
                }
            }
        }
        if let Some(orchestration) = &self.orchestration {
            orchestration
                .validate()
                .map_err(|error| error.to_string())?;
            if orchestration.parent != self.identity
                || orchestration.state_fence != self.state_fence
            {
                return Err(
                    "a post-commit orchestration record is not bound to this parent operation and \
                     State Fence"
                        .to_owned(),
                );
            }
            if !orchestration.resolved() && self.recovery().is_none() {
                // The one invariant that makes a retained obligation visible: a
                // runtime obligation this operation still owns, whose owner
                // effect is not durably answered, can never be reported beside a
                // null recovery directive. `recovery` derives its directive from
                // the same record, so this check refuses any projection where the
                // two could disagree.
                return Err(
                    "an unanswered post-commit runtime obligation requires a recovery directive"
                        .to_owned(),
                );
            }
        }
        self.validate_phase_joins()?;
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

    /// Validates parent identity/fence and exact phase joins against the
    /// authenticated request the Kernel route admitted. The request's
    /// canonical hash is intentionally not compared with the Store hash: the
    /// caller commits the closed operation through its idempotency key, while
    /// the Store mints a distinct metadata-bound canonical request hash.
    pub fn validate_for_request(
        &self,
        request: &UserAutomationServiceRequest,
    ) -> Result<(), String> {
        request
            .context
            .validate()
            .map_err(|error| error.to_string())?;
        if request.intent.state_fence != request.context.state_fence
            || self.identity.operation_id != request.identity.operation_id
            || self.identity.idempotency_key != request.identity.idempotency_key
            || self.state_fence != request.context.state_fence
        {
            return Err(
                "UserAutomation transition belongs to another request or State Fence".to_owned(),
            );
        }
        self.validate_run_now_wake_readback(request)?;
        self.validate()
    }

    fn validate_run_now_wake_readback(
        &self,
        request: &UserAutomationServiceRequest,
    ) -> Result<(), String> {
        let Some(UserAutomationMutationResult::RunNow { invocation, .. }) =
            self.configuration.mutation_result()
        else {
            return Ok(());
        };
        let UserAutomationWakePhase::Published { readback } = &self.wake else {
            return Ok(());
        };

        let wake_request = run_now_wake_read_request(
            request.context.clone(),
            request.authenticated_principal.clone(),
            self.identity.clone(),
            invocation.clone(),
        );
        readback
            .validate_for(&wake_request)
            .map_err(|error| error.to_string())?;
        if readback.operation_id != self.identity.operation_id.as_str()
            || readback.idempotency_key != self.identity.idempotency_key
        {
            return Err(
                "UserAutomation wake readback identity does not match its committed parent"
                    .to_owned(),
            );
        }
        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "closed mutation phases and owner joins must be checked together"
    )]
    fn validate_phase_joins(&self) -> Result<(), String> {
        match &self.configuration {
            UserAutomationConfigurationPhase::Read { .. } => {
                if self.horizon.is_some()
                    || self.orchestration.is_some()
                    || !matches!(&self.wake, UserAutomationWakePhase::NotApplicable { .. })
                    || !matches!(
                        &self.execution,
                        UserAutomationExecutionPhase::NotApplicable { .. }
                    )
                {
                    return Err(
                        "a read-only UserAutomation result carries mutation phases".to_owned()
                    );
                }
            }
            UserAutomationConfigurationPhase::Committed { receipt, result }
            | UserAutomationConfigurationPhase::Replayed { receipt, result } => {
                receipt.validate().map_err(|error| error.to_string())?;
                if receipt.operation_id != self.identity.operation_id
                    || receipt.idempotency_key != self.identity.idempotency_key
                    || receipt.canonical_request_hash != self.identity.canonical_request_hash
                    || receipt.state_fence != self.state_fence
                    || receipt.status != WriteReceiptStatus::Committed
                {
                    return Err(
                        "UserAutomation configuration receipt is not bound to its parent"
                            .to_owned(),
                    );
                }
                receipt
                    .require_reconciliation_envelope()
                    .map_err(|error| error.to_string())?;
                match result.as_ref() {
                    UserAutomationMutationResult::Revision {
                        revision,
                        cancelled_wake_ids,
                    } => {
                        revision.validate().map_err(|error| error.to_string())?;
                        if !matches!(
                            &self.execution,
                            UserAutomationExecutionPhase::NotApplicable { .. }
                        ) {
                            return Err(
                                "a revision mutation carries a foreign execution phase".to_owned()
                            );
                        }
                        // The committed `cancelled_wake_ids` is the canonical
                        // Store's OWN claim about what it cancelled, and that
                        // writer issues no wake effect, so it is empty for every
                        // committed mutation (I11.12: "Configuration state and
                        // execution state are separate"). The wake phase is the
                        // WAKE OWNER's answer, and it is the only place the
                        // owner's exact cancelled set exists. Requiring the two
                        // to be equal therefore compares the owner answer
                        // against a field that is structurally always empty,
                        // which would refuse every proven non-empty
                        // cancellation and turn it into a route-level unknown.
                        // What this join must still prove is that the wake
                        // phase does not CONTRADICT the commit: every wake
                        // identity the Store itself claims to have cancelled is
                        // covered by the owner-proven set. The owner set is
                        // separately bound to independent owner evidence —
                        // `UserAutomationOrchestrationRecord::validate_answer`
                        // compares it by exact ordered equality with the target
                        // batch of the retained Host enumeration receipt — so
                        // this check adds the commit's own claims to that
                        // binding instead of replacing it.
                        match &self.wake {
                            UserAutomationWakePhase::Cancelled {
                                cancelled_wake_ids: observed,
                            } if cancelled_wake_ids
                                .iter()
                                .all(|claimed| observed.contains(claimed)) => {}
                            UserAutomationWakePhase::NotApplicable { .. }
                                if cancelled_wake_ids.is_empty() => {}
                            UserAutomationWakePhase::UnknownOutcome { .. }
                            | UserAutomationWakePhase::Unavailable { .. } => {}
                            _ => {
                                return Err("UserAutomation wake phase does not join its mutation"
                                    .to_owned());
                            }
                        }
                        if let Some(horizon) = &self.horizon
                            && (horizon.automation_id != revision.automation_id
                                || horizon.automation_revision != revision.revision
                                || horizon.revision_digest
                                    != revision.digest().map_err(|error| error.to_string())?)
                        {
                            return Err(
                                "UserAutomation horizon belongs to another committed revision"
                                    .to_owned(),
                            );
                        }
                        if let Some(orchestration) = &self.orchestration {
                            let expected_receipt_digest =
                                crate::commit_recovery::receipt_evidence_digest(receipt);
                            if orchestration.automation_id != revision.automation_id
                                || orchestration.automation_revision != revision.revision
                                || orchestration.revision_digest
                                    != revision.digest().map_err(|error| error.to_string())?
                                || orchestration.committed_receipt_digest != expected_receipt_digest
                            {
                                return Err("UserAutomation orchestration is not bound to its committed revision and receipt".to_owned());
                            }
                        }
                    }
                    UserAutomationMutationResult::RunNow {
                        invocation,
                        wake_intent,
                    } => {
                        invocation.validate().map_err(|error| error.to_string())?;
                        wake_intent.validate().map_err(|error| error.to_string())?;
                        if wake_intent.state_fence != self.state_fence
                            || self.horizon.is_some()
                            || self.orchestration.is_some()
                        {
                            return Err("RunNow phases are not bound to the committed occurrence"
                                .to_owned());
                        }
                        let occurrence_id = invocation
                            .occurrence_identity()
                            .map_err(|error| error.to_string())?;
                        // The committed `WakeIntent` is the owner record the
                        // Durable Job admission binds this occurrence through, so
                        // it must name the occurrence it was committed beside.
                        // That check is what lets a proven-absence wake phase
                        // stand beside an execution join: the absence is about
                        // the Host journal's published calendar wakes, and the
                        // committed intent is the separate owner record that
                        // does bind this manual occurrence.
                        if wake_intent.wake_id != occurrence_id
                            || wake_intent.state != WakeIntentState::Pending
                        {
                            return Err(
                                "RunNow committed wake intent does not name its committed occurrence"
                                    .to_owned(),
                            );
                        }
                        match &self.wake {
                            UserAutomationWakePhase::Published { readback }
                                if readback.intent == *wake_intent
                                    && !readback.operation_id.trim().is_empty()
                                    && !readback.idempotency_key.trim().is_empty()
                                    && !readback.record_checksum.trim().is_empty() => {}
                            // The wake owner is the sole writer of the Host
                            // journal, and it publishes only the calendar
                            // occurrences the immutable revision compiles. An
                            // explicit manual `run-now` nonce is deliberately
                            // outside that set (I11.12:33), so its proven
                            // absence is the correct answer beside a committed
                            // occurrence whose own owner record binds it. A
                            // retained readback still has to equal that
                            // committed intent in full above.
                            UserAutomationWakePhase::NotApplicable { .. } => {}
                            UserAutomationWakePhase::UnknownOutcome { .. }
                            | UserAutomationWakePhase::Unavailable { .. } => {}
                            _ => {
                                return Err(
                                    "RunNow wake phase does not join the committed wake intent"
                                        .to_owned(),
                                );
                            }
                        }
                        // A wake phase that names this occurrence — the owner's
                        // retained record or its complete negative — is what an
                        // admitted, blocked, or unresolved execution may sit
                        // beside. An unresolved wake proves neither and never
                        // admits an occurrence.
                        let wake_proven = matches!(
                            &self.wake,
                            UserAutomationWakePhase::Published { .. }
                                | UserAutomationWakePhase::NotApplicable { .. }
                        );
                        match &self.execution {
                            UserAutomationExecutionPhase::Admitted { execution }
                                if execution.occurrence_id == occurrence_id && wake_proven => {}
                            UserAutomationExecutionPhase::Deferred { reason }
                                if wake_proven
                                    || (matches!(
                                        &self.wake,
                                        UserAutomationWakePhase::UnknownOutcome { .. }
                                            | UserAutomationWakePhase::Unavailable { .. }
                                    ) && matches!(
                                        reason,
                                        UserAutomationDeferReason::Paused
                                            | UserAutomationDeferReason::Retired
                                    )) => {}
                            UserAutomationExecutionPhase::BlockedConfig { .. }
                            | UserAutomationExecutionPhase::UnknownOutcome { .. }
                                if wake_proven => {}
                            UserAutomationExecutionPhase::Unavailable { .. } => {}
                            _ => {
                                return Err(
                                    "RunNow execution phase does not join its committed occurrence"
                                        .to_owned(),
                                );
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Returns the exact revision identity a committed or replayed configuration
/// mutation produced, if this phase is one.
fn committed_revision_id(phase: &UserAutomationConfigurationPhase) -> Option<String> {
    match phase.mutation_result()? {
        UserAutomationMutationResult::Revision { revision, .. } => Some(revision.revision.clone()),
        UserAutomationMutationResult::RunNow { .. } => None,
    }
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
/// owner port calls to the existing [`UserAutomationHostExecutionClient`] bound
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
    /// Publishes one bounded recurring horizon through the same authenticated
    /// Host transport every other owner call on this adapter uses.
    ///
    /// This override is load-bearing: the operator route reaches
    /// `publish_wake_horizon` through the `UserAutomationWakePort` trait on this
    /// concrete type, so without it the Create/Edit/Resume handoff would resolve
    /// to the trait default and answer `Unavailable` no matter what the client
    /// publishes. It forwards to the client's own trait implementation, which is
    /// bound to the client's single transport, so this adapter adds no second
    /// transport path and no second wake owner.
    async fn publish_wake_horizon(
        &self,
        request: impl Into<Box<UserAutomationWakeHorizonPublication>>,
    ) -> Result<UserAutomationWakePublication, UserAutomationRuntimeError> {
        UserAutomationWakePort::publish_wake_horizon(self.client, request).await
    }

    /// Reconciles one exact horizon publication with the schedule owner. Like
    /// the other readbacks here it resolves through the client's trait
    /// implementation, and it issues no owner effect: a caller that crossed an
    /// unknown boundary re-presents the same publication identity rather than
    /// publishing the slice again.
    async fn read_wake_horizon_publication(
        &self,
        request: impl Into<Box<UserAutomationWakeHorizonPublication>>,
    ) -> Result<UserAutomationWakePublication, UserAutomationRuntimeError> {
        UserAutomationWakePort::read_wake_horizon_publication(self.client, request).await
    }

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

    async fn cancel_pending_wakes_observed(
        &self,
        request: impl Into<Box<UserAutomationWakeCancellation>>,
        observer: &dyn UserAutomationHostExecutionObserver,
    ) -> Result<Vec<String>, UserAutomationRuntimeError> {
        UserAutomationWakePort::cancel_pending_wakes_observed(self.client, request, observer).await
    }

    async fn read_cancellation_batch(
        &self,
        request: impl Into<Box<UserAutomationWakeCancellation>>,
    ) -> Result<UserAutomationAuthenticatedWakeCancellationReadback, UserAutomationRuntimeError>
    {
        UserAutomationWakePort::read_cancellation_batch(self.client, request).await
    }

    async fn enumerate_pending_wakes(
        &self,
        request: impl Into<Box<UserAutomationWakeEnumerationRequest>>,
    ) -> Result<UserAutomationWakeEnumerationReceipt, UserAutomationRuntimeError> {
        UserAutomationWakePort::enumerate_pending_wakes(self.client, request).await
    }
}

impl<T> UserAutomationRuntimePort for UserAutomationOperatorRuntime<'_, T>
where
    T: UserAutomationHostExecutionTransport,
{
    async fn admit_occurrence(
        &self,
        mut request: UserAutomationRuntimeAdmission,
    ) -> Result<AutomationExecutionReference, UserAutomationRuntimeError> {
        request
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let occurrence_id = request
            .invocation
            .occurrence_identity()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        // The Host Durable Job owner admits a complete K0 submission. When the
        // caller did not supply one, this boundary compiles it from the admitted
        // revision and the committed source receipt the preflight receipt
        // already carries: the qualified artifact identity, its certified
        // capability profile, the declared Skill/Tool closure, the requester,
        // the bound scope/authority/session/epoch, the declared route, cost
        // ceiling and runtime ceiling, and the committed admission receipt. No
        // value is asserted on any owner's behalf and nothing is defaulted, so
        // the same closure, the same fence and the same occurrence identity
        // reach the owner. A material the Durable Job owner itself issued still
        // travels unchanged: this only fills the absent case.
        if request.durable_job.is_none() {
            request.durable_job = Some(
                UserAutomationDurableJobMaterial::from_admitted_occurrence(&request).map_err(
                    |error| {
                        UserAutomationRuntimeError::Rejected(format!(
                            "occurrence {occurrence_id} admitted by preflight but has no \
                             derivable Durable Job submission: {error}"
                        ))
                    },
                )?,
            );
            request
                .validate()
                .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
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

    async fn cancel_pending_wakes_observed(
        &self,
        request: UserAutomationWakeCancellation,
        observer: &dyn UserAutomationHostExecutionObserver,
    ) -> Result<Vec<String>, UserAutomationRuntimeError> {
        request
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        UserAutomationWakePort::cancel_pending_wakes_observed(self.client, request, observer).await
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
