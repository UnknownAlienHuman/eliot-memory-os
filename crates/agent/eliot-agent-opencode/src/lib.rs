#![forbid(unsafe_code)]

mod catalogue;
mod client;
mod endpoint;
mod gate;
mod http;
mod sse;
mod types;

pub use catalogue::*;
pub use client::{OpenCodeClient, OpenCodeRunError, OpenCodeRunPolicy};
pub use endpoint::{LoopbackEndpoint, LoopbackEndpointError};
pub use gate::{
    GateToolClass, GateValidationError, OPENCODE_ARGUMENT_NORMALIZATION_VERSION,
    OPENCODE_EFFECT_SCHEMA_VERSION, OPENCODE_GATE_EVENT_KIND, OPENCODE_GATE_PAYLOAD_FIELDS,
    OPENCODE_MAX_ARGUMENT_KEYS, OPENCODE_MAX_ARGUMENT_KEY_LENGTH,
    OPENCODE_MAX_EFFECT_DESCRIPTOR_BYTES, OPENCODE_MUTATING_TOOLS, OPENCODE_READ_ONLY_TOOLS,
    OPENCODE_SKIPPED_EVENT_KIND, OPENCODE_TOOL_IDENTITY_VERSION, ValidatedMutationGate,
    ValidatedSkippedReceipt, classify_opencode_tool, recompute_effect_digest,
    validate_mutation_gate_payload, validate_skipped_tool_receipt,
};
pub use http::{
    BasicAuth, HttpMethod, HttpRequest, HttpResponse, LoopbackHttpClient, LoopbackHttpError,
    SseConnection,
};
pub use sse::{ReconnectCursor, SseDecodeError, SseDecoder, SseEvent, SseLimits};
pub use types::*;
