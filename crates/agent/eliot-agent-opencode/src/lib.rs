#![forbid(unsafe_code)]

mod client;
mod endpoint;
mod http;
mod sse;
mod types;

pub use client::{OpenCodeClient, OpenCodeRunError, OpenCodeRunPolicy};
pub use endpoint::{LoopbackEndpoint, LoopbackEndpointError};
pub use http::{
    BasicAuth, HttpMethod, HttpRequest, HttpResponse, LoopbackHttpClient, LoopbackHttpError,
    SseConnection,
};
pub use sse::{ReconnectCursor, SseDecodeError, SseDecoder, SseEvent, SseLimits};
pub use types::*;
