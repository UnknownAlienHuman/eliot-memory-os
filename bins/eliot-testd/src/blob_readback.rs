//! Authenticated, chunked Blob readback adapter for typed Testd sources.
//!
//! The exchange implementation is supplied by the authenticated Kernel IPC
//! client. This layer only issues the closed source-readback request and
//! assembles owner-returned contiguous bytes; it has no Blob identity or
//! RequestIdentity minting path.

use std::future::Future;
use std::pin::Pin;

use eliot_blob_api::wire::{
    PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES, ProcessStreamSourceReadbackRequest as BlobRequest,
    ProcessStreamSourceReadbackResponse as BlobResponse,
};
use eliot_contracts::{ClockReading, canonical_json_bytes};
use eliot_process::{DurableStreamLocatorKind, ProcessStreamKind};
use eliot_testd_core::{
    AsyncProcessStreamSourceReadbackPort, ProcessStreamSourceReadbackFuture,
    ProcessStreamSourceReadbackObservation, ProcessStreamSourceReadbackRequest, TestdEvidenceError,
    TestdStreamDisposition, sha256_hex,
};
use serde::Serialize;

/// Future returned by the authenticated Kernel source-readback exchange.
pub type BlobReadbackExchangeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<BlobResponse, TestdEvidenceError>> + Send + 'a>>;

/// One typed source-readback exchange over the already authenticated Kernel
/// session. The implementation supplies owner-issued per-operation identity.
pub trait BlobReadbackExchange: Send + Sync {
    /// Requests one bounded chunk from the exact retained source.
    fn read_source_chunk<'a>(&'a self, request: &'a BlobRequest) -> BlobReadbackExchangeFuture<'a>;
}

/// Adapts the Kernel-owned chunk exchange to Testd's verified ephemeral-byte
/// boundary.
pub struct KernelBlobReadbackPort<E> {
    exchange: E,
}

impl<E> KernelBlobReadbackPort<E> {
    /// Uses the supplied authenticated Kernel exchange.
    pub const fn new(exchange: E) -> Self {
        Self { exchange }
    }
}

impl<E: BlobReadbackExchange> AsyncProcessStreamSourceReadbackPort for KernelBlobReadbackPort<E> {
    fn resolve<'a>(
        &'a self,
        request: &'a ProcessStreamSourceReadbackRequest,
    ) -> ProcessStreamSourceReadbackFuture<'a> {
        Box::pin(async move { self.read_verified_source(request).await })
    }
}

impl<E: BlobReadbackExchange> KernelBlobReadbackPort<E> {
    async fn read_verified_source(
        &self,
        request: &ProcessStreamSourceReadbackRequest,
    ) -> Result<ProcessStreamSourceReadbackObservation, TestdEvidenceError> {
        request.validate()?;
        let stream = request.stream;
        if request.expected_byte_length > eliot_blob_api::BLOB_MAX_PLAINTEXT_BYTES {
            return Err(integrity_error(stream));
        }
        let process_binding_json = canonical_json(&request.binding)?;
        let policy_json = serde_json::to_string(&request.policy).map_err(|_| {
            TestdEvidenceError::BindingMismatch {
                reason: "the admitted stream policy could not be serialized",
            }
        })?;
        let policy: eliot_blob_api::wire::ProcessStreamPolicyBinding =
            serde_json::from_str(&policy_json).map_err(|_| invalid_stream(stream))?;
        let mut offset = 0_u64;
        let mut bytes = Vec::new();
        bytes
            .try_reserve(
                usize::try_from(request.expected_byte_length)
                    .map_err(|_| integrity_error(stream))?,
            )
            .map_err(|_| integrity_error(stream))?;
        let mut owner_generation = None;
        let mut readback_receipt_id: Option<String> = None;
        let mut observed_fence = None;
        let mut observed_at = None;

        loop {
            let wire_request = BlobRequest {
                wire_revision: 1,
                job_id: request.job_id.clone(),
                invocation_id: request.invocation_id.clone(),
                operation_id: request.binding.operation_id().as_str().to_owned(),
                process_tree_id: request.binding.process_tree_id().as_str().to_owned(),
                process_binding_json: process_binding_json.clone(),
                process_binding_sha256: sha256_hex(process_binding_json.as_bytes()),
                stream: match stream {
                    ProcessStreamKind::Stdout => eliot_blob_api::wire::ProcessStreamKind::Stdout,
                    ProcessStreamKind::Stderr => eliot_blob_api::wire::ProcessStreamKind::Stderr,
                },
                locator_kind: match request.locator_kind {
                    DurableStreamLocatorKind::Blob => {
                        eliot_blob_api::wire::DurableStreamLocatorKind::Blob
                    }
                    DurableStreamLocatorKind::ImmutableArtifact => {
                        eliot_blob_api::wire::DurableStreamLocatorKind::ImmutableArtifact
                    }
                },
                locator: request.locator.clone(),
                ready_receipt_ref: request.ready_receipt_ref.clone(),
                expected_sha256: request.expected_sha256.clone(),
                expected_byte_length: request.expected_byte_length,
                policy: policy.clone(),
                policy_json: policy_json.clone(),
                policy_sha256: sha256_hex(policy_json.as_bytes()),
                fence: request.fence.clone(),
                max_bytes: request.max_bytes,
                offset,
                chunk_limit: PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES,
                deadline_ms: request.deadline_ms,
            };
            wire_request
                .validate()
                .map_err(|_| invalid_stream(stream))?;
            let response = self.exchange.read_source_chunk(&wire_request).await?;
            let (
                chunk,
                chunk_offset,
                observed_sha256,
                observed_byte_length,
                ready_receipt_ref,
                response_generation,
                response_receipt,
                response_fence,
                observed_at_unix_ms,
            ) = match response {
                BlobResponse::Ready {
                    bytes,
                    chunk_offset,
                    observed_sha256,
                    observed_byte_length,
                    ready_receipt_ref,
                    source_owner_generation,
                    readback_receipt_id,
                    observed_fence,
                    observed_at_unix_ms,
                } => (
                    bytes,
                    chunk_offset,
                    observed_sha256,
                    observed_byte_length,
                    ready_receipt_ref,
                    source_owner_generation,
                    readback_receipt_id,
                    observed_fence,
                    observed_at_unix_ms,
                ),
                BlobResponse::Unknown => {
                    return Err(TestdEvidenceError::SourceUnknownOutcome {
                        stream,
                        reason: "the owner could not establish the stored-source readback outcome",
                    });
                }
                BlobResponse::NotStarted => {
                    return Err(TestdEvidenceError::SourceUnavailable {
                        stream,
                        reason: "the owner proved the source readback did not start",
                    });
                }
            };
            if chunk_offset != offset
                || chunk.len() > PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES as usize
                || observed_byte_length != chunk.len() as u64
                || observed_sha256 != sha256_hex(&chunk)
                || ready_receipt_ref != request.ready_receipt_ref
                || response_generation == 0
                || observed_at_unix_ms == 0
                || observed_at_unix_ms > request.deadline_ms
            {
                return Err(integrity_error(stream));
            }
            if owner_generation.is_some_and(|value| value != response_generation)
                || readback_receipt_id
                    .as_deref()
                    .is_some_and(|value| value != response_receipt.as_str())
                || observed_fence
                    .as_ref()
                    .is_some_and(|value: &eliot_contracts::StateFence| value != &response_fence)
                || observed_at.is_some_and(|value| value != observed_at_unix_ms)
            {
                return Err(integrity_error(stream));
            }
            owner_generation = Some(response_generation);
            readback_receipt_id = Some(response_receipt);
            observed_fence = Some(response_fence);
            observed_at = Some(observed_at_unix_ms);

            let new_len = offset
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| integrity_error(stream))?;
            if new_len > request.expected_byte_length || new_len > request.max_bytes {
                return Err(integrity_error(stream));
            }
            if chunk.is_empty() && new_len != request.expected_byte_length {
                return Err(integrity_error(stream));
            }
            bytes.extend_from_slice(&chunk);
            offset = new_len;
            if offset == request.expected_byte_length {
                break;
            }
        }

        if bytes.len() as u64 != request.expected_byte_length
            || sha256_hex(&bytes) != request.expected_sha256
        {
            return Err(integrity_error(stream));
        }
        let observed_at_unix_ms = observed_at.ok_or_else(|| integrity_error(stream))?;
        let observed_at_unix_ms =
            i64::try_from(observed_at_unix_ms).map_err(|_| integrity_error(stream))?;
        Ok(ProcessStreamSourceReadbackObservation::new(
            bytes,
            request.expected_sha256.clone(),
            request.expected_byte_length,
            request.locator_kind,
            request.locator.clone(),
            request.ready_receipt_ref.clone(),
            owner_generation.ok_or_else(|| integrity_error(stream))?,
            readback_receipt_id.ok_or_else(|| integrity_error(stream))?,
            observed_fence.ok_or_else(|| integrity_error(stream))?,
            ClockReading {
                valid_time_ms: Some(observed_at_unix_ms),
                known_time_ms: Some(observed_at_unix_ms),
                transaction_sequence: None,
                monotonic_ns: None,
            },
            TestdStreamDisposition::CompleteSource,
        ))
    }
}

fn canonical_json(value: &impl Serialize) -> Result<String, TestdEvidenceError> {
    let bytes = canonical_json_bytes(value).map_err(|_| TestdEvidenceError::BindingMismatch {
        reason: "the admitted source binding could not be canonically serialized",
    })?;
    String::from_utf8(bytes).map_err(|_| TestdEvidenceError::BindingMismatch {
        reason: "the canonical source binding is not UTF-8 JSON",
    })
}

fn invalid_stream(stream: ProcessStreamKind) -> TestdEvidenceError {
    TestdEvidenceError::ReadbackRequestInvalid {
        field: "process_stream_source",
        reason: match stream {
            ProcessStreamKind::Stdout => "the stdout source request is invalid",
            ProcessStreamKind::Stderr => "the stderr source request is invalid",
        },
    }
}

fn integrity_error(stream: ProcessStreamKind) -> TestdEvidenceError {
    TestdEvidenceError::SourceIntegrityBroken {
        stream,
        reason: "chunk offsets, per-chunk integrity, receipt, fence, length, or whole-source digest disagree",
    }
}
