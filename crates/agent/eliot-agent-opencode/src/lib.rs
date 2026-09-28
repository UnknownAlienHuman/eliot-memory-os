#![forbid(unsafe_code)]

mod bridge_contract;
mod catalogue;
mod client;
mod endpoint;
mod gate;
mod http;
mod ingress;
mod pilot;
mod route_admission;
mod sse;
mod types;

pub use bridge_contract::{
    BridgeContractError, opencode_adapter_contract, validate_opencode_adapter_contract,
};
pub use catalogue::*;
pub use client::{
    AdmittedAttemptOutcome, OpenCodeClient, OpenCodeRunError, OpenCodeRunPolicy,
    classify_sealed_candidate, redact_route_diagnostics,
};
pub use endpoint::{LoopbackEndpoint, LoopbackEndpointError};
pub use gate::{
    GateToolClass, GateValidationError, OPENCODE_ARGUMENT_NORMALIZATION_VERSION,
    OPENCODE_EFFECT_SCHEMA_VERSION, OPENCODE_GATE_EVENT_KIND, OPENCODE_GATE_PAYLOAD_FIELDS,
    OPENCODE_MAX_ARGUMENT_KEY_LENGTH, OPENCODE_MAX_ARGUMENT_KEYS,
    OPENCODE_MAX_EFFECT_DESCRIPTOR_BYTES, OPENCODE_MUTATING_TOOLS, OPENCODE_READ_ONLY_TOOLS,
    OPENCODE_SKIPPED_EVENT_KIND, OPENCODE_TOOL_IDENTITY_VERSION, ValidatedMutationGate,
    ValidatedSkippedReceipt, classify_opencode_tool, recompute_effect_digest,
    validate_mutation_gate_payload, validate_skipped_tool_receipt,
};
pub use http::{
    BasicAuth, HttpMethod, HttpRequest, HttpResponse, LoopbackHttpClient, LoopbackHttpError,
    SseConnection,
};
pub use ingress::{
    ActionGate, ActionGateDecision, ActionGateError, ActionGateRequest, CredentialResolver,
    DECISION_ALLOW, DECISION_DENY, DECISION_RECORDED, DISPOSITION_DENIED,
    DISPOSITION_INVALID_REQUEST, DISPOSITION_RECOVERY_REQUIRED, DISPOSITION_STALE_OR_CONFLICT,
    DISPOSITION_UNAVAILABLE_OR_CAPACITY, DecisionReplay, EffectDecisionIdentity,
    HOST_EVENTS_BODY_TIMEOUT, HOST_EVENTS_ERROR_VERSION, HOST_EVENTS_HEAD_TIMEOUT,
    HOST_EVENTS_PATH, HOST_EVENTS_PAYLOAD_TYPE, HOST_EVENTS_PRODUCER_ID,
    HOST_EVENTS_RESPONSE_VERSION, HOST_EVENTS_STREAM_ID, HostEventAdmission,
    HostEventAdmissionError, HostEventAdmissionFailure, HostEventAdmissionReceipt,
    HostEventDelivery, HostEventGap, HostEventKind, HostEventPorts, HostEventReject,
    HostEventResponseFields, HostEventSubmission, HostEventsBindError, HostEventsListener,
    HostEventsShutdown, HttpOutcome, IntroductionStore, MAX_BEARER_BYTES, MAX_EVENT_ID_BYTES,
    MAX_HOST_EVENT_BODY_BYTES, MAX_HOST_EVENT_HEAD_BYTES, MAX_HOST_EVENT_HEADERS,
    MAX_IDEMPOTENCY_KEY_BYTES, MAX_PASSIVE_EVENT_FIELDS, ParsedHostEventHead,
    REASON_AUTHENTICATION_REQUIRED, REASON_AUTHORITY_REQUIRED, REASON_BUSY,
    REASON_CAPABILITY_GRANT_REVOKED, REASON_CAPABILITY_INTRODUCTION_REQUIRED,
    REASON_CAPABILITY_UNAVAILABLE, REASON_DB_UNAVAILABLE, REASON_DEADLINE_EXCEEDED,
    REASON_IDENTITY_CONFLICT, REASON_INVALID_ARGUMENT, REASON_POLICY_DENIED,
    REASON_PROTOCOL_INCOMPATIBLE, REASON_ROUTE_UNAVAILABLE, REASON_SCOPE_CONFLICT,
    REASON_STALE_AUTHORITY_EPOCH, REASON_STALE_STATE_FENCE, REASON_STORAGE_BACKPRESSURE,
    UnconfiguredActionGate, authority_epoch_text, classify_decision_replay, effect_request_hash,
    encode_host_event_response, handle_host_event, parse_http_head, response_commitment,
    response_commitment_message, verify_response_commitment,
};
pub use pilot::opencode_pilot_observation;
pub use route_admission::{
    OPENCODE_MANDATED_PROBES, OPENCODE_ROUTE_ADMISSION_SCHEMA_VERSION, OpenCodePilotObservation,
    OpenCodeProbeOutcome, OpenCodeProbeReading, OpenCodeRouteAdmission,
    OpenCodeRouteAdmissionState, OpenCodeRouteProbeEvidence, OpenCodeRouteProfile,
    OpenCodeRouteRole, OpenCodeRouteSelectionError, RGF_AGENT_ROUTES,
    opencode_pilot_probe_evidence, opencode_route_role_permitted, select_opencode_route,
};
pub use sse::{ReconnectCursor, SseDecodeError, SseDecoder, SseEvent, SseLimits};
pub use types::*;
