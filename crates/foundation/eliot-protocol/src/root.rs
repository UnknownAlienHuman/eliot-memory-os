#![forbid(unsafe_code)]

#[allow(
    dead_code,
    deprecated,
    reason = "the v1 protocol implementation remains a temporary public compatibility surface"
)]
#[path = "lib.rs"]
mod protocol_v1;

pub use protocol_v1::*;

mod maintenance_trigger;
pub use maintenance_trigger::{
    MAINTENANCE_TRIGGER_ACK_WIRE_ID, MAINTENANCE_TRIGGER_ACK_WIRE_VERSION,
    MAINTENANCE_TRIGGER_CLAIM_WIRE_ID, MAINTENANCE_TRIGGER_CLAIM_WIRE_VERSION,
    MAINTENANCE_TRIGGER_CONTRACT_NAME, MAINTENANCE_TRIGGER_CONTRACT_VERSION,
    MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_ID,
    MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_VERSION, MAINTENANCE_TRIGGER_INTAKE_RECEIPT_WIRE_ID,
    MAINTENANCE_TRIGGER_INTAKE_RECEIPT_WIRE_VERSION, MAINTENANCE_TRIGGER_PAGE_WIRE_ID,
    MAINTENANCE_TRIGGER_PAGE_WIRE_VERSION, MAINTENANCE_TRIGGER_REVOCATION_WIRE_ID,
    MAINTENANCE_TRIGGER_REVOCATION_WIRE_VERSION, MAINTENANCE_TRIGGER_ROUTE_GRANT_WIRE_ID,
    MAINTENANCE_TRIGGER_ROUTE_GRANT_WIRE_VERSION, MAINTENANCE_TRIGGER_TERMINAL_DISPOSITION_WIRE_ID,
    MAINTENANCE_TRIGGER_TERMINAL_DISPOSITION_WIRE_VERSION, MAINTENANCE_TRIGGER_WIRE_ID,
    MAINTENANCE_TRIGGER_WIRE_VERSION, MAX_MAINTENANCE_TRIGGER_PAGE_GAPS,
    MAX_MAINTENANCE_TRIGGER_PAGE_MEMBERS, MaintenanceTriggerAck, MaintenanceTriggerClaim,
    MaintenanceTriggerContentRef, MaintenanceTriggerDecisionReceipt, MaintenanceTriggerDisposition,
    MaintenanceTriggerGap, MaintenanceTriggerGapKind, MaintenanceTriggerIntakeOutcome,
    MaintenanceTriggerIntakeReceipt, MaintenanceTriggerPage, MaintenanceTriggerPayloadRef,
    MaintenanceTriggerPendingSummary, MaintenanceTriggerPosition, MaintenanceTriggerRecord,
    MaintenanceTriggerRevocation, MaintenanceTriggerRoute, MaintenanceTriggerRouteGrant,
    MaintenanceTriggerRoutingClass, MaintenanceTriggerSourceEvent,
    MaintenanceTriggerTerminalDisposition, MaintenanceTriggerTerminalKind,
    maintenance_trigger_contract_identity,
};

pub mod activation_resolution_v1;

mod reason_codes;
pub use reason_codes::{
    AGENT_REASON_CODES, AgentReasonCode, BRIDGE_REASON_CODE_ALIASES, agent_reason_code,
    bridge_reason_code_alias,
};

mod activation_resolution;
pub use activation_resolution::{
    AGENT_ACTIVATION_CLAIM_WIRE_ID, AGENT_ACTIVATION_CLAIM_WIRE_VERSION, AGENT_ACTIVATION_OWNER_ID,
    AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_ID, AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_VERSION,
    AGENT_ACTIVATION_RESULT_ACK_WIRE_ID, AGENT_ACTIVATION_RESULT_ACK_WIRE_VERSION,
    AGENT_ACTIVATION_RESULT_RECONCILE_WIRE_ID, AGENT_ACTIVATION_RESULT_RECONCILE_WIRE_VERSION,
    AGENT_ACTIVATION_RESULT_SUBMIT_WIRE_ID, AGENT_ACTIVATION_RESULT_SUBMIT_WIRE_VERSION,
    AgentActivationCandidateCoverage, AgentActivationClaimRequest,
    AgentActivationColdStartQuestion, AgentActivationDependencyObservation,
    AgentActivationKernelOwnerReadback, AgentActivationOwnerEvidence, AgentActivationOwnerReadback,
    AgentActivationResolutionDisposition, AgentActivationResolutionResult,
    AgentActivationResolvedBinding, AgentActivationResultAck, AgentActivationResultAckOutcome,
    AgentActivationResultReconcile, AgentActivationResultSubmit, AgentActivationRetryDirective,
    AgentActivationSelectionDirective, MAX_AGENT_ACTIVATION_CANDIDATES, binding_digest,
    decode_agent_activation_result_submit,
};

mod invalid_ticket;
pub use invalid_ticket::{
    AGENT_ACTIVATION_INVALID_TICKET_WIRE_ID, AGENT_ACTIVATION_INVALID_TICKET_WIRE_VERSION,
    AgentActivationInvalidTicket, MAX_INVALID_TICKET_BYTES, UNKNOWN_INVALID_TICKET_ID,
};

mod host_event_ingest;
pub use host_event_ingest::{
    HOST_EVENT_INGEST_RECORD_WIRE_ID, HOST_EVENT_INGEST_RECORD_WIRE_VERSION,
    HOST_EVENT_STREAM_CURSOR_WIRE_ID, HOST_EVENT_STREAM_CURSOR_WIRE_VERSION,
    HostEventIngestDispositionWire, HostEventIngestRecordWire, HostEventRedactionReceiptWire,
    HostEventStreamCursorWire, MAX_HOST_EVENT_INGEST_TEXT_BYTES, MAX_HOST_EVENT_REDACTED_CLASSES,
    MAX_HOST_EVENT_STREAM_ID_BYTES,
};

mod task_controller;
pub use task_controller::{
    TASK_CONTROLLER_ATTEMPT_WIRE_ID, TASK_CONTROLLER_ATTEMPT_WIRE_VERSION,
    TASK_CONTROLLER_INVOCATION_WIRE_ID, TASK_CONTROLLER_INVOCATION_WIRE_VERSION,
    TASK_CONTROLLER_INVOCATION_LEGACY_WIRE_VERSION,
    TASK_CONTROLLER_RESULT_BODY_WIRE_ID, TASK_CONTROLLER_RESULT_BODY_WIRE_VERSION,
    TaskControllerAction, TaskControllerAttempt, TaskControllerCampaignOwnerMaterials,
    TaskControllerInvocation, TaskControllerOrientationInput,
    TaskControllerOrientationMaterialBudget, TaskControllerOrientationOutputSchemaRecipe,
    TaskControllerOrientationSourceClaim,
    TaskControllerResultBody,
};

mod finish_attempt;
pub use finish_attempt::{
    FINISH_ATTEMPT_WIRE_ID, FINISH_ATTEMPT_WIRE_VERSION, FINISH_INVOKE_PAYLOAD_SCHEMA_ID,
    FINISH_RESULT_BODY_WIRE_ID, FINISH_RESULT_BODY_WIRE_VERSION, FinishAttempt, FinishResultBody,
};

pub mod route_continuation;
pub use route_continuation::{
    ContinuityKind, HandoffCausalLink, HandoffCompleteness, InFlightEffectDisposition,
    MAX_ROUTE_CONTINUATION_HANDLES, MAX_ROUTE_CONTINUATION_IN_FLIGHT_DISPOSITIONS,
    MAX_ROUTE_CONTINUATION_OPAQUE_STATE_BYTES, MAX_ROUTE_CONTINUATION_TEXT_BYTES,
    ROUTE_CONTINUATION_CONTRACT_NAME, ROUTE_CONTINUATION_CONTRACT_VERSION,
    ROUTE_CONTINUATION_PAYLOAD_TYPE, RehydrationBundle, RouteContinuationDeletionReason,
    RouteContinuationState, RouteFingerprint, route_continuation_contract_identity,
};
