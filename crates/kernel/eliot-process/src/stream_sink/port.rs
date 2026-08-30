use std::future::Future;
use std::pin::Pin;

use super::ProcessStreamSinkError;
use super::requests::{
    ProcessStreamSinkAbortRequest, ProcessStreamSinkAppend, ProcessStreamSinkAppendDisposition,
    ProcessStreamSinkFinalizeRequest, ProcessStreamSinkOpenRequest, ProcessStreamSinkReadback,
};
use super::terminal::{ProcessStreamSinkSession, ProcessStreamSinkTerminal};

/// One explicitly sendable future shape for every provider-neutral sink call.
pub type ProcessStreamSinkFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ProcessStreamSinkError>> + Send + 'a>>;

/// Provider-neutral process stream persistence session port.
pub trait ProcessStreamSinkClient: Send + Sync {
    fn open(
        &self,
        request: ProcessStreamSinkOpenRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkSession>;

    fn append(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAppend,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkAppendDisposition>;

    fn finalize(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkFinalizeRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal>;

    fn abort(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAbortRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal>;

    fn readback(
        &self,
        session: ProcessStreamSinkSession,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback>;
}
