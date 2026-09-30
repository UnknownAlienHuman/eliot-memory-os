//! Bounded readback of the original Kernel process executor's retained bytes.
//!
//! This module is deliberately not a durable BlobStore reader. The current
//! P-03 gateway constructs its original executor without a stream sink, so the
//! only complete source it can truthfully serve is the original P-04 capture
//! when it retained every byte through EOF. Prefix previews and captures that
//! exceeded the executor's retained capacity remain incomplete.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_kernel_core::ProcessExecutionReplayState;
use eliot_kernel_service::{
    PROCESS_STREAM_READBACK_MAX_BYTES, ProcessStreamReadChunk, ProcessStreamReadRequest,
};
use eliot_process::{
    ProcessExecutionError, ProcessOwnerBinding, ProcessStreamEvidence, ProcessStreamKind,
    StreamEvidenceGap, StreamPersistenceStatus, StreamPreviewRepresentation, StreamTransportStatus,
};
use eliot_process_executor::CapturedStream;

use super::process_execution::ProcessExecutionGateway;

fn unknown() -> ProcessExecutionError {
    ProcessExecutionError::UnknownOutcome
}

fn select_stream(
    evidence: &eliot_process::ProcessEvidence,
    stream: ProcessStreamKind,
) -> Result<&ProcessStreamEvidence, ProcessExecutionError> {
    let selected = match stream {
        ProcessStreamKind::Stdout => evidence.stdout(),
        ProcessStreamKind::Stderr => evidence.stderr(),
    }
    .ok_or_else(unknown)?;
    selected.validate().map_err(|_| unknown())?;
    Ok(selected)
}

fn require_exact_capture(
    evidence: &ProcessStreamEvidence,
    capture: &CapturedStream,
) -> Result<(), ProcessExecutionError> {
    let disallowed_gap = evidence.gaps().iter().any(|gap| {
        !matches!(
            gap,
            StreamEvidenceGap::PersistenceUnavailable
                | StreamEvidenceGap::PersistenceBackpressure
                | StreamEvidenceGap::PersistenceFailed
                | StreamEvidenceGap::PersistenceUnknownOutcome
        )
    });
    if evidence.transport() != StreamTransportStatus::Complete
        || evidence.persistence() != StreamPersistenceStatus::SourceUnavailable
        || evidence.source().is_some()
        || evidence.transport_prefix_identity().is_some()
        || disallowed_gap
        || !capture.captured
        || !capture.complete
        || capture.truncated
        || capture.bytes.len() as u64 != capture.total_bytes
        || capture.total_bytes != evidence.observed_bytes()
        || capture.total_bytes > PROCESS_STREAM_READBACK_MAX_BYTES
        || sha256_hex(&capture.bytes) != evidence.observed_sha256()
    {
        return Err(unknown());
    }

    // A withheld preview is a policy decision, not permission to expose the
    // same bytes through another wire shape. When a transport preview exists,
    // ensure the original capture begins with those exact observed bytes.
    match evidence.preview().representation() {
        StreamPreviewRepresentation::TransportBytes => {
            let preview = evidence.preview().bytes();
            if capture.bytes.get(..preview.len()) != Some(preview) {
                return Err(unknown());
            }
        }
        StreamPreviewRepresentation::WithheldByPolicy
        | StreamPreviewRepresentation::DurableSourceBytes => return Err(unknown()),
    }
    Ok(())
}

/// Reads a single bounded page only after re-establishing the exact original
/// start receipt, authenticated owner, terminal process view, and typed
/// stream evidence. No preview bytes are promoted into a complete source.
pub(crate) async fn read_stream_chunk(
    gateway: &ProcessExecutionGateway,
    owner: &ProcessOwnerBinding,
    request: ProcessStreamReadRequest,
) -> Result<ProcessStreamReadChunk, ProcessExecutionError> {
    request
        .validate()
        .map_err(|_| eliot_process::ContractError::DispatchBindingMismatch)?;
    let receipt = request.start_receipt();
    receipt.validate()?;
    let operation_id = receipt.operation_id().clone();

    let record = gateway
        .replay_store
        .load_process_start(&operation_id)
        .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?
        .ok_or(ProcessExecutionError::NotFound)?;
    super::process_execution::authorize_process_owner(&record.owner, owner)?;
    if record.state != ProcessExecutionReplayState::Completed
        || record.receipt.as_ref() != Some(receipt)
    {
        return Err(unknown());
    }

    // Preserve the ordinary authenticated Inspect boundary: this API never
    // turns an in-flight process into a completed stream merely because a
    // byte prefix is currently available.
    let view = gateway.inspect(owner, operation_id.clone()).await?;
    if view.operation_id() != &operation_id
        || view.binding() != receipt.binding()
        || !view.lifecycle().is_terminal()
        || view.identity() != Some(receipt.identity())
    {
        return Err(unknown());
    }

    // Reconcile through the same original P-03 owner so this read cannot
    // observe an unrelated caller-provided ProcessEvidence value.
    let process_evidence = gateway.reconcile(owner, operation_id.clone()).await?;
    process_evidence.validate().map_err(|_| unknown())?;
    if process_evidence.operation_id() != &operation_id
        || process_evidence.binding() != receipt.binding()
        || !process_evidence.view().lifecycle().is_terminal()
        || process_evidence.view().identity() != Some(receipt.identity())
    {
        return Err(unknown());
    }

    let stream_evidence = select_stream(&process_evidence, request.stream())?;
    if stream_evidence.binding() != receipt.binding()
        || stream_evidence.stream() != request.stream()
    {
        return Err(unknown());
    }
    let (stdout, stderr) = gateway.executor.captured_output(&operation_id)?;
    let capture = match request.stream() {
        ProcessStreamKind::Stdout => &stdout,
        ProcessStreamKind::Stderr => &stderr,
    };
    require_exact_capture(stream_evidence, capture)?;

    let offset = usize::try_from(request.offset()).map_err(|_| unknown())?;
    let maximum = usize::try_from(request.max_bytes()).map_err(|_| unknown())?;
    let end = offset
        .checked_add(maximum)
        .ok_or_else(unknown)?
        .min(capture.bytes.len());
    if offset > end {
        return Err(unknown());
    }
    let bytes = capture.bytes[offset..end].to_vec();
    let start_receipt_sha256 = sha256_hex(&canonical_json_bytes(receipt).map_err(|_| unknown())?);
    let stream_evidence_sha256 = stream_evidence.identity_sha256().map_err(|_| unknown())?;
    ProcessStreamReadChunk::from_owner_readback(
        operation_id,
        receipt.binding().clone(),
        request.stream(),
        start_receipt_sha256,
        stream_evidence_sha256,
        stream_evidence.observed_sha256().to_owned(),
        stream_evidence.observed_bytes(),
        capture.complete,
        request.offset(),
        bytes,
    )
    .map_err(|_| unknown())
}
