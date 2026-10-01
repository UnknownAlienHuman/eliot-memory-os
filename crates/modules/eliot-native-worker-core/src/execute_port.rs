//! Provider-neutral execution hook for the admitted native-worker Execute
//! contour.
//!
//! The core owns frame validation, durable request replay, and ordinary
//! Accepted/CandidateOnly events. A composed provider owner may attach one
//! hook to perform the separately admitted provider operation after those
//! checks. This seam carries the validated EBP frame only; it conveys no
//! provider material, process request, credential, or authority.

use std::future::Future;
use std::pin::Pin;

use crate::{NativeWorkerRetainedOperationOutcome, WorkerError, WorkerFrame, WorkerRequest};

/// Asynchronous owner hook for a frame that has passed `WorkerCore`'s
/// lifecycle, frame-binding, capability, effect, and durable-replay gates.
///
/// The provider owner must source all provider inputs from its own
/// authenticated retained-material path. `WorkerRequest::payload` is an
/// ordinary EBP field and must not be promoted to provider authority.
pub trait NativeWorkerExecutePort: Send + Sync {
    /// Executes one exact admitted worker request through the composed
    /// provider owner. A retained terminal is returned unchanged for the
    /// ordinary durable worker event stream; it is never promoted to task
    /// completion. Implementations return only after the provider result has
    /// either reached the canonical result owner or been retained as an
    /// unknown/refused outcome under the original operation.
    fn execute<'a>(
        &'a self,
        frame: &'a WorkerFrame,
        request: &'a WorkerRequest,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<NativeWorkerRetainedOperationOutcome>, WorkerError>>
                + Send
                + 'a,
        >,
    >;
}
