use std::sync::Arc;

use eliot_process::{
    PROCESS_STREAM_SINK_SCHEMA_VERSION, ProcessStreamDigestAlgorithm,
    ProcessStreamSinkAbortRequest, ProcessStreamSinkAppend, ProcessStreamSinkClient,
    ProcessStreamSinkError, ProcessStreamSinkFinalizeRequest, ProcessStreamSinkFuture,
    ProcessStreamSinkLimits, ProcessStreamSinkOpenRequest, ProcessStreamSinkReadback,
    ProcessStreamSinkSession, ProcessStreamSinkSessionId, ProcessStreamSinkSourceId,
    ProcessStreamSinkTerminal, ProcessStreamSinkTerminalCommandIdentity,
    ProcessStreamSinkTerminalCommandKind, ProcessStreamSinkTerminalId,
};

fn accepts_object_safe_client(_: Arc<dyn ProcessStreamSinkClient>) {}

#[test]
fn sink_contract_is_public_and_object_safe() {
    assert_eq!(
        PROCESS_STREAM_SINK_SCHEMA_VERSION,
        "eliot-process-stream-sink-v1"
    );
    let _: Option<ProcessStreamSinkFuture<'static, ProcessStreamSinkSession>> = None;
    let _: Option<ProcessStreamSinkFuture<'static, ProcessStreamSinkTerminal>> = None;
    let _: Option<ProcessStreamSinkFuture<'static, ProcessStreamSinkReadback>> = None;
    let _: Option<ProcessStreamSinkError> = None;
    let _: Option<ProcessStreamSinkOpenRequest> = None;
    let _: Option<ProcessStreamSinkAppend> = None;
    let _: Option<ProcessStreamSinkFinalizeRequest> = None;
    let _: Option<ProcessStreamSinkAbortRequest> = None;
    let _: Option<ProcessStreamSinkLimits> = None;
    let _: Option<ProcessStreamSinkSessionId> = None;
    let _: Option<ProcessStreamSinkSourceId> = None;
    let _: Option<ProcessStreamSinkTerminalId> = None;
    let _: Option<ProcessStreamSinkTerminalCommandIdentity> = None;
    let _: Option<ProcessStreamSinkTerminalCommandKind> = None;
    let _: Option<ProcessStreamDigestAlgorithm> = None;
    accepts_object_safe_client(Arc::new(NoopClient));
}

struct NoopClient;

impl ProcessStreamSinkClient for NoopClient {
    fn open(
        &self,
        _request: ProcessStreamSinkOpenRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkSession> {
        Box::pin(async { Err(ProcessStreamSinkError::ProviderUnavailable) })
    }

    fn append(
        &self,
        _session: ProcessStreamSinkSession,
        _request: ProcessStreamSinkAppend,
    ) -> ProcessStreamSinkFuture<'_, eliot_process::ProcessStreamSinkAppendDisposition> {
        Box::pin(async { Err(ProcessStreamSinkError::ProviderUnavailable) })
    }

    fn finalize(
        &self,
        _session: ProcessStreamSinkSession,
        _request: ProcessStreamSinkFinalizeRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal> {
        Box::pin(async { Err(ProcessStreamSinkError::ProviderUnavailable) })
    }

    fn abort(
        &self,
        _session: ProcessStreamSinkSession,
        _request: ProcessStreamSinkAbortRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal> {
        Box::pin(async { Err(ProcessStreamSinkError::ProviderUnavailable) })
    }

    fn readback(
        &self,
        _session: ProcessStreamSinkSession,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback> {
        Box::pin(async { Err(ProcessStreamSinkError::ProviderUnavailable) })
    }
}
