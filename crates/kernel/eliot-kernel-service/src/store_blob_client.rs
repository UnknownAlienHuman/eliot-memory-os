//! Authenticated EBP transport for the distinct S-04 process-stream readback
//! wire. The method shares the already admitted Store connection and never
//! opens or authenticates a second transport.

use eliot_blob_api::wire::{
    BLOB_PROCESS_STREAM_CAPABILITY, BlobProcessStreamFrameRequest, BlobProcessStreamFrameResponse,
    BlobProcessStreamOperationRequest, BlobProcessStreamOperationResponse,
    PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES, ProcessStreamSinkWireRequest,
    ProcessStreamSinkWireResponse, ProcessStreamSourceReadbackRequest,
    ProcessStreamSourceReadbackReady, ProcessStreamSourceReadbackResponse,
};
use eliot_contracts::StateFence;
use eliot_ipc::DeliveryOutcome;
use eliot_protocol::{Frame, FrameKind, MessageType, ProtocolPayload, RequestIdentity};

use super::{EbpCanonicalStoreClient, EbpStoreTransport, StoreClientError};

impl<T: EbpStoreTransport + 'static> EbpCanonicalStoreClient<T> {
    /// Sends one exact operation over the separately negotiated Blob process-stream
    /// capability, using this client's existing authenticated Store EBP session.
    ///
    /// The caller must provide the Kernel-issued per-operation request identity.
    /// An uncertain frame is never retried here; the server retains the operation
    /// identity and its exact outcome for a later reconciliation request.
    pub async fn process_stream_exchange(
        &self,
        request: BlobProcessStreamFrameRequest,
        identity: RequestIdentity,
    ) -> Result<BlobProcessStreamFrameResponse, StoreClientError> {
        request
            .validate()
            .map_err(|error| StoreClientError::Contract(error.to_string()))?;
        identity
            .validate()
            .map_err(|error| StoreClientError::Contract(error.to_string()))?;
        if !self.blob_process_stream_capability {
            return Err(StoreClientError::Contract(format!(
                "Store did not negotiate {BLOB_PROCESS_STREAM_CAPABILITY}"
            )));
        }
        let (fence, deadline_ms) = match &request.operation {
            BlobProcessStreamOperationRequest::Sink { request } => sink_request_identity(request),
            BlobProcessStreamOperationRequest::SourceReadback { request } => {
                (&request.fence, request.deadline_ms)
            }
        };
        if fence != &identity.request.state_fence
            || fence != &self.requirement.state_fence
            || deadline_ms != identity.deadline_unix_ms
        {
            return Err(StoreClientError::Contract(
                "Blob process-stream operation is outside the authenticated request fence or deadline"
                    .to_owned(),
            ));
        }

        let request_id = identity.request.metadata.request_id.clone();
        let frame = Frame {
            protocol_version: self.protocol_version,
            encoding_profile: eliot_protocol::EncodingProfile::JsonV1,
            connection_id: self.requirement.connection_id.as_str().to_owned(),
            request_id: Some(request_id.clone()),
            kind: FrameKind::Request,
            message_type: MessageType::Execute,
            request_identity: Some(identity),
            payload: ProtocolPayload::Json(serde_json::to_value(&request).map_err(|error| {
                StoreClientError::Contract(format!(
                    "Blob process-stream request serialization failed: {error}"
                ))
            })?),
            trace_context: Default::default(),
        };
        frame
            .validate()
            .map_err(|error| StoreClientError::Contract(error.to_string()))?;

        // Keep each request/response pair atomic on the shared connection.
        let mut transport = self.transport.lock().await;
        match transport.send_frame(&frame, self.limits).await {
            Ok(DeliveryOutcome::Delivered) => {}
            Ok(DeliveryOutcome::UnknownOutcome) | Err(_) => {
                return Err(StoreClientError::BlobProcessStreamUnknownOutcome);
            }
        }
        let response = transport
            .receive_frame(self.limits)
            .await
            .map_err(|_| StoreClientError::BlobProcessStreamUnknownOutcome)?;
        let decoded = decode_blob_frame_response(
            &response,
            self.requirement.connection_id.as_str(),
            self.protocol_version,
            &request_id,
        )
        .map_err(|_| StoreClientError::BlobProcessStreamUnknownOutcome)?;
        decoded
            .validate()
            .map_err(|_| StoreClientError::BlobProcessStreamUnknownOutcome)?;
        let expected_family_matches = matches!(
            (&request.operation, &decoded.operation),
            (
                BlobProcessStreamOperationRequest::Sink { .. },
                BlobProcessStreamOperationResponse::Sink { .. }
            ) | (
                BlobProcessStreamOperationRequest::SourceReadback { .. },
                BlobProcessStreamOperationResponse::SourceReadback { .. }
            )
        );
        if !expected_family_matches {
            return Err(StoreClientError::BlobProcessStreamUnknownOutcome);
        }
        Ok(decoded)
    }

    /// Sends one closed sink operation through the separately negotiated Blob
    /// process-stream capability.
    pub async fn process_stream_sink_exchange(
        &self,
        request: ProcessStreamSinkWireRequest,
        identity: RequestIdentity,
    ) -> Result<ProcessStreamSinkWireResponse, StoreClientError> {
        request
            .validate()
            .map_err(|error| StoreClientError::Contract(error.to_string()))?;
        let response = self
            .process_stream_exchange(
                BlobProcessStreamFrameRequest {
                    wire_id: eliot_blob_api::wire::BLOB_PROCESS_STREAM_WIRE_ID.to_owned(),
                    wire_revision: eliot_blob_api::wire::BLOB_PROCESS_STREAM_WIRE_REVISION,
                    operation: BlobProcessStreamOperationRequest::Sink {
                        request: Box::new(request),
                    },
                },
                identity,
            )
            .await;
        let response = match response {
            Ok(response) => response,
            Err(StoreClientError::BlobProcessStreamUnknownOutcome) => {
                return Ok(ProcessStreamSinkWireResponse::Unknown);
            }
            Err(error) => return Err(error),
        };
        let BlobProcessStreamOperationResponse::Sink { response } = response.operation else {
            return Err(StoreClientError::Contract(
                "Blob sink response had the wrong operation family".to_owned(),
            ));
        };
        Ok(response)
    }

    /// Sends one bounded semantic readback chunk over this client's existing
    /// authenticated Store EBP session.
    ///
    /// `identity` must be issued by the Kernel request-authority path and is
    /// checked against the process source fence and deadline. Every uncertain
    /// send, receive, or response remains [`ProcessStreamSourceReadbackResponse::Unknown`];
    /// this method never repeats a request.
    pub async fn readback_process_stream_chunk(
        &self,
        request: ProcessStreamSourceReadbackRequest,
        identity: RequestIdentity,
    ) -> Result<ProcessStreamSourceReadbackResponse, StoreClientError> {
        request
            .validate()
            .map_err(|error| StoreClientError::Contract(error.to_string()))?;
        identity
            .validate()
            .map_err(|error| StoreClientError::Contract(error.to_string()))?;
        if request.fence != identity.request.state_fence
            || request.fence != self.requirement.state_fence
            || request.deadline_ms != identity.deadline_unix_ms
        {
            return Err(StoreClientError::Contract(
                "Blob readback request is outside the authenticated request fence or deadline"
                    .to_owned(),
            ));
        }

        let exchange = self
            .process_stream_exchange(
                BlobProcessStreamFrameRequest {
                    wire_id: eliot_blob_api::wire::BLOB_PROCESS_STREAM_WIRE_ID.to_owned(),
                    wire_revision: eliot_blob_api::wire::BLOB_PROCESS_STREAM_WIRE_REVISION,
                    operation: BlobProcessStreamOperationRequest::SourceReadback {
                        request: Box::new(request.clone()),
                    },
                },
                identity,
            )
            .await;
        let Ok(exchange) = exchange else {
            return Ok(ProcessStreamSourceReadbackResponse::Unknown);
        };
        let BlobProcessStreamOperationResponse::SourceReadback { response: decoded } =
            exchange.operation
        else {
            return Ok(ProcessStreamSourceReadbackResponse::Unknown);
        };
        if !valid_chunk_response(&request, &decoded) {
            return Ok(ProcessStreamSourceReadbackResponse::Unknown);
        }
        Ok(*decoded)
    }
}

fn decode_blob_frame_response(
    frame: &Frame,
    expected_connection_id: &str,
    expected_protocol: eliot_protocol::ProtocolVersion,
    expected_request_id: &eliot_contracts::RequestId,
) -> Result<BlobProcessStreamFrameResponse, StoreClientError> {
    frame
        .validate()
        .map_err(|error| StoreClientError::Contract(error.to_string()))?;
    if frame.protocol_version != expected_protocol
        || frame.connection_id != expected_connection_id
        || frame.kind != FrameKind::Response
        || frame.message_type != MessageType::Result
        || frame.request_id.as_ref() != Some(expected_request_id)
        || frame.request_identity.is_some()
        || frame.encoding_profile != eliot_protocol::EncodingProfile::JsonV1
    {
        return Err(StoreClientError::Contract(
            "Blob readback response is outside the authenticated request exchange".to_owned(),
        ));
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err(StoreClientError::Contract(
            "Blob readback response must use its closed JSON wire contract".to_owned(),
        ));
    };
    serde_json::from_value(payload.clone())
        .map_err(|error| StoreClientError::Contract(error.to_string()))
}

fn sink_request_identity(request: &ProcessStreamSinkWireRequest) -> (&StateFence, u64) {
    match request {
        ProcessStreamSinkWireRequest::Open {
            fence, deadline_ms, ..
        }
        | ProcessStreamSinkWireRequest::Append {
            fence, deadline_ms, ..
        }
        | ProcessStreamSinkWireRequest::Finalize {
            fence, deadline_ms, ..
        }
        | ProcessStreamSinkWireRequest::Abort {
            fence, deadline_ms, ..
        }
        | ProcessStreamSinkWireRequest::Readback {
            fence, deadline_ms, ..
        }
        | ProcessStreamSinkWireRequest::Reconcile {
            fence, deadline_ms, ..
        } => (fence, *deadline_ms),
    }
}

fn valid_chunk_response(
    request: &ProcessStreamSourceReadbackRequest,
    response: &ProcessStreamSourceReadbackResponse,
) -> bool {
    match response {
        ProcessStreamSourceReadbackResponse::NotStarted
        | ProcessStreamSourceReadbackResponse::Unknown => true,
        ProcessStreamSourceReadbackResponse::Ready(ready) => {
            let ProcessStreamSourceReadbackReady {
                bytes,
                chunk_offset,
                observed_sha256,
                observed_byte_length,
                ready_receipt_ref,
                source_owner_generation,
                readback_receipt_id,
                observed_fence,
                observed_at_unix_ms,
                ..
            } = ready.as_ref();
            *chunk_offset == request.offset
                && bytes.len() <= PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES as usize
                && chunk_offset.saturating_add(bytes.len() as u64) <= request.expected_byte_length
                && *observed_byte_length == bytes.len() as u64
                && observed_sha256 == &eliot_contracts::sha256_hex(bytes)
                && ready_receipt_ref == &request.ready_receipt_ref
                && *source_owner_generation > 0
                && !readback_receipt_id.trim().is_empty()
                && *observed_fence == request.fence
                && *observed_at_unix_ms > 0
                && (request.expected_byte_length == 0 || !bytes.is_empty())
        }
    }
}
