//! Authenticated, chunked Blob readback adapter for typed Testd sources.
//!
//! The exchange implementation is supplied by the authenticated Kernel IPC
//! client. This layer only issues the closed source-readback request and
//! assembles owner-returned contiguous bytes; it has no Blob identity or
//! RequestIdentity minting path.

use std::future::Future;
use std::pin::Pin;

use crate::kernel_client::{KernelBlobStreamCallSequence, TestdIpcError};
use eliot_blob_api::wire::{
    BlobProcessStreamKernelOperationRequest as KernelOperation, BlobProcessStreamKernelOutcome,
    BlobProcessStreamKernelResponse,
    BlobProcessStreamKernelSourceReadbackRequest as KernelSourceRequest,
    BlobProcessStreamOperationResponse, PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES,
    ProcessStreamSourceReadbackResponse as BlobResponse,
};
use eliot_contracts::{ClockReading, canonical_json_bytes};
use eliot_process::{DurableStreamLocatorKind, ProcessStreamKind};
use eliot_testd_core::{
    AsyncProcessStreamSourceReadbackPort, ProcessStreamSourceReadbackFuture,
    ProcessStreamSourceReadbackObservation, ProcessStreamSourceReadbackRequest,
    TestdBlobProcessStreamReadyReceipt, TestdEvidenceError, TestdReplayOwnerReadback,
    TestdStreamDisposition, sha256_hex,
};
use serde::Serialize;

/// Future returned by the authenticated Kernel source-readback exchange.
pub type BlobReadbackExchangeFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<BlobProcessStreamKernelResponse, TestdEvidenceError>>
            + Send
            + 'a,
    >,
>;

/// One typed source-readback exchange over the already authenticated Kernel
/// session. The implementation supplies owner-issued per-operation identity.
pub trait BlobReadbackExchange: Send + Sync {
    /// Requests one bounded chunk from the exact retained source.
    fn read_source_chunk<'a>(
        &'a self,
        request: &'a KernelSourceRequest,
    ) -> BlobReadbackExchangeFuture<'a>;

    /// Resolves the exact retained Finalize receipt under its durable call
    /// row; the selector must include the admitted process and stream IDs.
    fn retained_ready_finalize_receipt(
        &self,
        process_binding_sha256: &str,
        session_id: &str,
        source_id: &str,
        terminal_id: &str,
        ready_receipt_ref: &str,
    ) -> Result<Option<TestdBlobProcessStreamReadyReceipt>, TestdEvidenceError>;
}

impl BlobReadbackExchange for KernelBlobStreamCallSequence {
    fn read_source_chunk<'a>(
        &'a self,
        request: &'a KernelSourceRequest,
    ) -> BlobReadbackExchangeFuture<'a> {
        let calls = self.clone();
        let request = request.clone();
        let stream = request.stream;
        Box::pin(async move {
            match tokio::task::spawn_blocking(move || {
                calls.exchange(KernelOperation::SourceReadback { request })
            })
            .await
            {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(error)) => Err(map_ipc_error(error, stream)),
                Err(_) => Err(TestdEvidenceError::SourceUnknownOutcome {
                    stream,
                    reason: "the authenticated Kernel readback task ended without a proven result",
                }),
            }
        })
    }

    fn retained_ready_finalize_receipt(
        &self,
        process_binding_sha256: &str,
        session_id: &str,
        source_id: &str,
        terminal_id: &str,
        ready_receipt_ref: &str,
    ) -> Result<Option<TestdBlobProcessStreamReadyReceipt>, TestdEvidenceError> {
        self.lookup_retained_ready_finalize_receipt(
            process_binding_sha256,
            session_id,
            source_id,
            terminal_id,
            ready_receipt_ref,
        )
        .map_err(|_| TestdEvidenceError::BindingMismatch {
            reason: "the exact Finalize Ready receipt is absent or conflicted in the durable call ledger",
        })
    }
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
        let mut replay_owner_readback: Option<TestdReplayOwnerReadback> = None;

        loop {
            let wire_request = KernelSourceRequest {
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
                max_bytes: request.max_bytes,
                offset,
                chunk_limit: PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES,
                deadline_ms: request.deadline_ms,
            };
            wire_request
                .validate()
                .map_err(|_| invalid_stream(stream))?;
            let kernel_response = self.exchange.read_source_chunk(&wire_request).await?;
            let response = match kernel_response.outcome {
                BlobProcessStreamKernelOutcome::Completed { response, .. } => {
                    match response.operation {
                        BlobProcessStreamOperationResponse::SourceReadback { response } => response,
                        _ => return Err(integrity_error(stream)),
                    }
                }
                BlobProcessStreamKernelOutcome::Unknown { .. } => {
                    return Err(TestdEvidenceError::SourceUnknownOutcome {
                        stream,
                        reason: "the Kernel could not establish the stored-source readback outcome",
                    });
                }
                BlobProcessStreamKernelOutcome::NotStarted { .. }
                | BlobProcessStreamKernelOutcome::Unavailable { .. } => {
                    return Err(TestdEvidenceError::SourceUnavailable {
                        stream,
                        reason: "the Kernel refused the stored-source readback before a result",
                    });
                }
            };
            let (
                chunk,
                whole_source_sha256,
                whole_source_byte_length,
                chunk_offset,
                observed_sha256,
                observed_byte_length,
                ready_receipt_ref,
                response_generation,
                response_receipt,
                response_fence,
                observed_at_unix_ms,
                owner_facts_json,
                owner_facts_sha256,
                module_catalog_owner_readback_json,
                module_catalog_owner_readback_sha256,
                generation_admission_json,
                generation_admission_sha256,
                process_source_admission_readback_json,
                process_source_admission_readback_sha256,
                source_admission_write_receipt_json,
                source_admission_write_receipt_sha256,
            ) = match response {
                BlobResponse::Ready {
                    bytes,
                    whole_source_sha256,
                    whole_source_byte_length,
                    chunk_offset,
                    observed_sha256,
                    observed_byte_length,
                    ready_receipt_ref,
                    source_owner_generation,
                    readback_receipt_id,
                    observed_fence,
                    observed_at_unix_ms,
                    owner_facts_json,
                    owner_facts_sha256,
                    module_catalog_owner_readback_json,
                    module_catalog_owner_readback_sha256,
                    generation_admission_json,
                    generation_admission_sha256,
                    process_source_admission_readback_json,
                    process_source_admission_readback_sha256,
                    source_admission_write_receipt_json,
                    source_admission_write_receipt_sha256,
                } => (
                    bytes,
                    whole_source_sha256,
                    whole_source_byte_length,
                    chunk_offset,
                    observed_sha256,
                    observed_byte_length,
                    ready_receipt_ref,
                    source_owner_generation,
                    readback_receipt_id,
                    observed_fence,
                    observed_at_unix_ms,
                    owner_facts_json,
                    owner_facts_sha256,
                    module_catalog_owner_readback_json,
                    module_catalog_owner_readback_sha256,
                    generation_admission_json,
                    generation_admission_sha256,
                    process_source_admission_readback_json,
                    process_source_admission_readback_sha256,
                    source_admission_write_receipt_json,
                    source_admission_write_receipt_sha256,
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
            let source_admission_write_receipt_json =
                source_admission_write_receipt_json.ok_or_else(|| integrity_error(stream))?;
            let source_admission_write_receipt_sha256 =
                source_admission_write_receipt_sha256.ok_or_else(|| integrity_error(stream))?;
            if chunk_offset != offset
                || whole_source_sha256 != request.expected_sha256
                || whole_source_byte_length != request.expected_byte_length
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
            {
                return Err(integrity_error(stream));
            }
            let current_owner_readback = TestdReplayOwnerReadback {
                process_source_admission_readback_json,
                process_source_admission_readback_sha256,
                source_admission_write_receipt_json,
                source_admission_write_receipt_sha256,
                finalized_blob_ready_receipt_json: None,
                finalized_blob_ready_receipt_sha256: None,
                owner_facts_json,
                owner_facts_sha256,
                module_catalog_owner_readback_json,
                module_catalog_owner_readback_sha256,
                generation_admission_json,
                generation_admission_sha256,
            };
            current_owner_readback
                .validate()
                .map_err(|_| integrity_error(stream))?;
            if replay_owner_readback
                .as_ref()
                .is_some_and(|existing| existing != &current_owner_readback)
            {
                return Err(integrity_error(stream));
            }
            replay_owner_readback = Some(current_owner_readback);
            owner_generation = Some(response_generation);
            readback_receipt_id = Some(response_receipt);
            observed_fence = Some(response_fence);
            // This is the current read observation clock for this chunk. It
            // may advance between chunks and is never substituted for the
            // process capture or source commit clock.
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
        let process_binding_sha256 = sha256_hex(process_binding_json.as_bytes());
        let source_fence = observed_fence
            .as_ref()
            .ok_or_else(|| integrity_error(stream))?;
        let mut replay_owner = replay_owner_readback.ok_or_else(|| integrity_error(stream))?;
        self.bind_finalize_receipt(request, &process_binding_sha256, source_fence, &mut replay_owner)?;
        replay_owner.validate().map_err(|_| integrity_error(stream))?;
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
        )
        .with_replay_owner_readback(replay_owner))
    }

    fn bind_finalize_receipt(
        &self,
        request: &ProcessStreamSourceReadbackRequest,
        process_binding_sha256: &str,
        source_fence: &eliot_contracts::StateFence,
        owner: &mut TestdReplayOwnerReadback,
    ) -> Result<(), TestdEvidenceError> {
        use eliot_store_api::blob_process_source_admission::{
            BlobProcessSourceAdmissionIdentity, BlobProcessSourceAdmissionPhase,
            BlobProcessSourceAdmissionReadback,
        };

        let facts: eliot_blob_api::wire::BlobProcessStreamVerifiedOwnerFacts =
            serde_json::from_str(&owner.owner_facts_json).map_err(|_| integrity_error(request.stream))?;
        facts.validate().map_err(|_| integrity_error(request.stream))?;
        let scope: serde_json::Value = serde_json::from_str(&facts.work_scope_binding_json)
            .map_err(|_| integrity_error(request.stream))?;
        let work_scope_ref = scope
            .pointer("/binding/scope/scope_ref")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| integrity_error(request.stream))?;
        let work_scope_owner_revision = scope
            .get("owner_revision")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| integrity_error(request.stream))?;
        let work_scope_fence: eliot_contracts::StateFence = serde_json::from_value(
            scope
                .get("state_fence")
                .cloned()
                .ok_or_else(|| integrity_error(request.stream))?,
        )
        .map_err(|_| integrity_error(request.stream))?;
        let process_readback: BlobProcessSourceAdmissionReadback = serde_json::from_str(
            &owner.process_source_admission_readback_json,
        )
        .map_err(|_| integrity_error(request.stream))?;
        let admission = &process_readback.admission;
        let open: eliot_process::ProcessStreamSinkOpenRequest = serde_json::from_str(
            &admission.open_request_json,
        )
        .map_err(|_| integrity_error(request.stream))?;
        open.validate().map_err(|_| integrity_error(request.stream))?;
        let identity = BlobProcessSourceAdmissionIdentity {
            work_scope_ref: work_scope_ref.to_owned(),
            session_id: open.session_id().as_str().to_owned(),
            source_id: open.source_id().as_str().to_owned(),
            process_binding_sha256: process_binding_sha256.to_owned(),
        };
        process_readback
            .validate_for(&identity, request.binding.state_fence())
            .map_err(|_| integrity_error(request.stream))?;
        let ready = admission
            .ready
            .as_ref()
            .ok_or_else(|| integrity_error(request.stream))?;
        if admission.phase != BlobProcessSourceAdmissionPhase::Ready
            || process_readback.owner_revision != 2
            || admission.owner_revision != 2
            || admission.work_scope_owner_revision != work_scope_owner_revision
            || admission.work_scope_owner_digest
                != sha256_hex(facts.work_scope_binding_json.as_bytes())
            || admission.state_fence != *request.binding.state_fence()
            || work_scope_fence != *request.binding.state_fence()
            || process_readback.state_fence != *source_fence
            || admission.owner_facts_json != owner.owner_facts_json
            || admission.owner_facts_sha256 != owner.owner_facts_sha256
            || admission.process_binding_json != canonical_json(&request.binding)?
            || admission.process_binding_sha256 != process_binding_sha256
            || admission.open_request_sha256 != open.open_request_sha256()
            || open.binding() != &request.binding
            || open.stream() != request.stream
            || open.policy() != &request.policy
            || ready.whole_source_sha256 != request.expected_sha256
            || ready.whole_source_byte_length != request.expected_byte_length
        {
            return Err(integrity_error(request.stream));
        }
        let receipt = self
            .exchange
            .retained_ready_finalize_receipt(
                process_binding_sha256,
                &identity.session_id,
                &identity.source_id,
                open.terminal_id().as_str(),
                &request.ready_receipt_ref,
            )?
            .ok_or_else(|| integrity_error(request.stream))?;
        receipt.validate().map_err(|_| integrity_error(request.stream))?;
        if receipt.process_binding_sha256 != process_binding_sha256
            || receipt.binding_ref.is_empty()
            || receipt.session_id != identity.session_id
            || receipt.source_id != identity.source_id
            || receipt.terminal_id != open.terminal_id().as_str()
            || receipt.ready_receipt_ref != request.ready_receipt_ref
            || receipt.source_sha256 != request.expected_sha256
            || receipt.source_byte_length != request.expected_byte_length
            || receipt.receipt_json != ready.blob_ready_receipt_json
            || receipt.receipt_sha256 != ready.blob_ready_receipt_sha256
        {
            return Err(integrity_error(request.stream));
        }
        owner.finalized_blob_ready_receipt_json = Some(receipt.receipt_json);
        owner.finalized_blob_ready_receipt_sha256 = Some(receipt.receipt_sha256);
        Ok(())
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

fn map_ipc_error(error: TestdIpcError, stream: ProcessStreamKind) -> TestdEvidenceError {
    match error {
        TestdIpcError::UnknownOutcome { .. } => TestdEvidenceError::SourceUnknownOutcome {
            stream,
            reason: "the authenticated Kernel exchange outcome is unknown",
        },
        _ => TestdEvidenceError::SourceUnavailable {
            stream,
            reason: "the authenticated Kernel source-readback exchange was refused",
        },
    }
}
