//! Authenticated EBP transport for the distinct S-04 process-stream readback
//! wire. The method shares the already admitted Store connection and never
//! opens or authenticates a second transport.

use eliot_blob_api::wire::{
    PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES, ProcessStreamSourceReadbackRequest,
    ProcessStreamSourceReadbackResponse,
};
use eliot_ipc::DeliveryOutcome;
use eliot_protocol::{Frame, FrameKind, MessageType, ProtocolPayload, RequestIdentity};

use super::{EbpCanonicalStoreClient, EbpStoreTransport, StoreClientError};

impl<T: EbpStoreTransport + 'static> EbpCanonicalStoreClient<T> {
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

        let request_id = identity.request.metadata.request_id.clone();
        let frame = Frame {
            protocol_version: self.protocol_version,
            encoding_profile: eliot_protocol::EncodingProfile::JsonV1,
            connection_id: self.requirement.connection_id.as_str().to_owned(),
            request_id: Some(request_id.clone()),
            kind: FrameKind::Request,
            message_type: MessageType::Execute,
            request_identity: Some(identity),
            payload: ProtocolPayload::Json(
                serde_json::to_value(&request).map_err(|error| {
                    StoreClientError::Contract(format!(
                        "Blob readback request serialization failed: {error}"
                    ))
                })?,
            ),
            trace_context: Default::default(),
        };
        frame
            .validate()
            .map_err(|error| StoreClientError::Contract(error.to_string()))?;

        // Hold the existing connection lock across the whole exchange so a
        // canonical Store request cannot interleave with its response.
        let mut transport = self.transport.lock().await;
        match transport.send_frame(&frame, self.limits).await {
            Ok(DeliveryOutcome::Delivered) => {}
            Ok(DeliveryOutcome::UnknownOutcome) | Err(_) => {
                return Ok(ProcessStreamSourceReadbackResponse::Unknown);
            }
        }
        let response = match transport.receive_frame(self.limits).await {
            Ok(response) => response,
            Err(_) => return Ok(ProcessStreamSourceReadbackResponse::Unknown),
        };
        let decoded = decode_blob_response(
            &response,
            self.requirement.connection_id.as_str(),
            self.protocol_version,
            &request_id,
        );
        let Ok(decoded) = decoded else {
            return Ok(ProcessStreamSourceReadbackResponse::Unknown);
        };
        if !valid_chunk_response(&request, &decoded) {
            return Ok(ProcessStreamSourceReadbackResponse::Unknown);
        }
        Ok(decoded)
    }
}

fn decode_blob_response(
    frame: &Frame,
    expected_connection_id: &str,
    expected_protocol: eliot_protocol::ProtocolVersion,
    expected_request_id: &eliot_contracts::RequestId,
) -> Result<ProcessStreamSourceReadbackResponse, StoreClientError> {
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

fn valid_chunk_response(
    request: &ProcessStreamSourceReadbackRequest,
    response: &ProcessStreamSourceReadbackResponse,
) -> bool {
    match response {
        ProcessStreamSourceReadbackResponse::NotStarted
        | ProcessStreamSourceReadbackResponse::Unknown => true,
        ProcessStreamSourceReadbackResponse::Ready {
            bytes,
            chunk_offset,
            observed_sha256,
            observed_byte_length,
            ready_receipt_ref,
            source_owner_generation,
            readback_receipt_id,
            observed_fence,
            observed_at_unix_ms,
        } => {
            *chunk_offset == request.offset
                && bytes.len() <= PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES as usize
                && chunk_offset.saturating_add(bytes.len() as u64) <= *observed_byte_length
                && *observed_byte_length == request.expected_byte_length
                && observed_sha256 == &request.expected_sha256
                && ready_receipt_ref == &request.ready_receipt_ref
                && *source_owner_generation > 0
                && !readback_receipt_id.trim().is_empty()
                && *observed_fence == request.fence
                && *observed_at_unix_ms > 0
                && (request.expected_byte_length == 0 || !bytes.is_empty())
        }
    }
}
