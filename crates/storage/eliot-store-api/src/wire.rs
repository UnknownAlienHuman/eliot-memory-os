//! Bounded store-service payloads for the ELIOT Bridge Protocol.
//!
//! This module owns the semantic request/response catalogue.  The process
//! root owns only transport and handshake state; adapter SDKs, credentials,
//! query text, Blob bytes, lifecycle operations and maintenance services are
//! intentionally not representable here.

use std::collections::BTreeSet;

use eliot_contracts::RequestId;
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
    RequestIdentity,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    NamedReadRequest, NamedReadResponse, OperationId, OrderingHead, OrderingHeadExpectation,
    OrderingScopeId, PreparedTransition, RequestMeta, RevisionHead, RevisionHeadExpectation,
    RevisionKey, StoreError, StoreHealth, WriteReceipt,
};
use schemars::JsonSchema;

/// Hard bound for list fields crossing the store service boundary.
pub const MAX_STORE_WIRE_ITEMS: usize = 256;

pub const CAPABILITY_HEALTH: &str = "store.health";
pub const CAPABILITY_READINESS: &str = "store.readiness";
pub const CAPABILITY_NAMED_READ: &str = "store.named_read";
pub const CAPABILITY_APPLY: &str = "store.apply";
pub const CAPABILITY_RECEIPT: &str = "store.receipt";
pub const CAPABILITY_REVISION_HEADS: &str = "store.revision_heads";
pub const CAPABILITY_ORDERING_HEADS: &str = "store.ordering_heads";

/// Capabilities advertised by the canonical store process.
pub const CAPABILITIES: &[&str] = &[
    CAPABILITY_HEALTH,
    CAPABILITY_READINESS,
    CAPABILITY_NAMED_READ,
    CAPABILITY_APPLY,
    CAPABILITY_RECEIPT,
    CAPABILITY_REVISION_HEADS,
    CAPABILITY_ORDERING_HEADS,
];

/// Effects exposed by the canonical store process.
pub const EFFECTS: &[&str] = &["read", "canonical_write"];

/// Readiness is a bounded observation and not a semantic write authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    Unavailable,
    MigrationRequired,
    Ready,
}

/// Stable schema/readiness observation shared with Kernel clients.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessReceipt {
    pub status: ReadinessStatus,
    pub expected_generation: Option<String>,
    pub observed_generation: Option<String>,
}

impl ReadinessReceipt {
    pub fn unavailable() -> Self {
        Self {
            status: ReadinessStatus::Unavailable,
            expected_generation: None,
            observed_generation: None,
        }
    }

    pub fn migration_required(expected: String, observed: Option<String>) -> Self {
        Self {
            status: ReadinessStatus::MigrationRequired,
            expected_generation: Some(expected),
            observed_generation: observed,
        }
    }

    pub fn ready(generation: String) -> Self {
        Self {
            status: ReadinessStatus::Ready,
            expected_generation: Some(generation.clone()),
            observed_generation: Some(generation),
        }
    }

    pub fn validate(&self) -> Result<(), StoreWireError> {
        match self.status {
            ReadinessStatus::Unavailable => {
                if self.expected_generation.is_some() || self.observed_generation.is_some() {
                    return Err(StoreWireError::Invalid(
                        "unavailable readiness cannot carry schema generations".to_owned(),
                    ));
                }
            }
            ReadinessStatus::MigrationRequired => {
                validate_optional_text(&self.expected_generation, "expected_generation")?;
                validate_optional_text(&self.observed_generation, "observed_generation")?;
                if self.expected_generation.is_none() {
                    return Err(StoreWireError::Invalid(
                        "migration_required readiness needs expected_generation".to_owned(),
                    ));
                }
            }
            ReadinessStatus::Ready => {
                validate_optional_text(&self.expected_generation, "expected_generation")?;
                validate_optional_text(&self.observed_generation, "observed_generation")?;
                if self.expected_generation.is_none() || self.observed_generation.is_none() {
                    return Err(StoreWireError::Invalid(
                        "ready readiness needs both schema generations".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Closed semantic store request catalogue.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum StoreRequest {
    Health,
    Readiness,
    Named {
        request: NamedReadRequest,
    },
    Apply {
        context: RequestMeta,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    },
    Receipt {
        operation_id: OperationId,
    },
    RevisionHeads {
        keys: Vec<RevisionKey>,
    },
    OrderingHeads {
        scopes: Vec<OrderingScopeId>,
    },
}

impl StoreRequest {
    /// Validates the closed operation and all bounded list fields.
    pub fn validate(&self) -> Result<(), StoreError> {
        match self {
            Self::Health | Self::Readiness => Ok(()),
            Self::Named { request } => request.validate(),
            Self::Apply {
                context,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            } => {
                context.validate().map_err(StoreError::Foundation)?;
                transition.validate()?;
                if context.state_fence != transition.state_fence {
                    return Err(StoreError::FenceMismatch);
                }
                bounded_unique(expected_revision_heads, "expected_revision_heads", |head| {
                    head.key.clone()
                })?;
                bounded_unique(expected_ordering_heads, "expected_ordering_heads", |head| {
                    head.scope.clone()
                })?;
                for head in expected_revision_heads {
                    head.validate()?;
                    if head.state_fence != transition.state_fence {
                        return Err(StoreError::FenceMismatch);
                    }
                }
                for head in expected_ordering_heads {
                    head.validate()?;
                    if head.state_fence != transition.state_fence {
                        return Err(StoreError::FenceMismatch);
                    }
                }
                Ok(())
            }
            Self::Receipt { .. } => Ok(()),
            Self::RevisionHeads { keys } => bounded_unique(keys, "revision_keys", Clone::clone),
            Self::OrderingHeads { scopes } => {
                bounded_unique(scopes, "ordering_scopes", Clone::clone)
            }
        }
    }

    #[must_use]
    pub const fn capability(&self) -> &'static str {
        match self {
            Self::Health => CAPABILITY_HEALTH,
            Self::Readiness => CAPABILITY_READINESS,
            Self::Named { .. } => CAPABILITY_NAMED_READ,
            Self::Apply { .. } => CAPABILITY_APPLY,
            Self::Receipt { .. } => CAPABILITY_RECEIPT,
            Self::RevisionHeads { .. } => CAPABILITY_REVISION_HEADS,
            Self::OrderingHeads { .. } => CAPABILITY_ORDERING_HEADS,
        }
    }

    /// Binds the decoded payload to the authenticated EBP request identity.
    pub fn validate_for_identity(
        &self,
        request_id: &RequestId,
        identity: &RequestIdentity,
    ) -> Result<(), StoreWireError> {
        self.validate().map_err(StoreWireError::Store)?;
        identity
            .validate()
            .map_err(|error| StoreWireError::Protocol(error.to_string()))?;
        if request_id != &identity.request.metadata.request_id {
            return Err(StoreWireError::Identity(
                "frame request_id does not match request identity metadata".to_owned(),
            ));
        }
        match self {
            Self::Named { request } if request.state_fence != identity.request.state_fence => {
                Err(StoreWireError::Identity(
                    "named request fence does not match request identity".to_owned(),
                ))
            }
            Self::Apply {
                context,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            } => {
                if context != &identity.request.metadata {
                    return Err(StoreWireError::Identity(
                        "apply context does not match request identity metadata".to_owned(),
                    ));
                }
                if transition.identity.idempotency_key != identity.idempotency_key {
                    return Err(StoreWireError::Identity(
                        "prepared transition idempotency key does not match request identity"
                            .to_owned(),
                    ));
                }
                if transition.state_fence != identity.request.state_fence {
                    return Err(StoreWireError::Identity(
                        "prepared transition fence does not match request identity".to_owned(),
                    ));
                }
                for head in expected_revision_heads {
                    if head.state_fence != identity.request.state_fence {
                        return Err(StoreWireError::Identity(
                            "revision expectation fence does not match request identity".to_owned(),
                        ));
                    }
                }
                for head in expected_ordering_heads {
                    if head.state_fence != identity.request.state_fence {
                        return Err(StoreWireError::Identity(
                            "ordering expectation fence does not match request identity".to_owned(),
                        ));
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// Closed semantic store response catalogue.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum StoreResponse {
    Health {
        record: StoreHealth,
    },
    Readiness {
        receipt: ReadinessReceipt,
    },
    Named {
        response: NamedReadResponse,
    },
    Transaction {
        receipt: WriteReceipt,
    },
    Receipt {
        receipt: Option<WriteReceipt>,
    },
    RevisionHeads {
        heads: Vec<RevisionHead>,
    },
    OrderingHeads {
        heads: Vec<OrderingHead>,
    },
    /// Explicitly unknown/rejected reconciliation outcome; never a success.
    Unknown {
        operation_id: OperationId,
        reason: String,
    },
    Error {
        error: String,
    },
}

impl StoreResponse {
    /// Converts a write receipt into a reconciliation-safe response.
    pub fn from_transaction_receipt(receipt: WriteReceipt) -> Self {
        let reason = match receipt.validate() {
            Err(_) => Some("receipt_invalid"),
            Ok(()) => match receipt.require_reconciliation_envelope() {
                Ok(_) => None,
                Err(_) => Some("receipt_envelope_missing"),
            },
        };
        match reason {
            None => Self::Transaction { receipt },
            Some(reason) => Self::Unknown {
                operation_id: receipt.operation_id.clone(),
                reason: reason.to_owned(),
            },
        }
    }

    /// Converts an exact-operation lookup into a reconciliation-safe response.
    pub fn from_receipt(receipt: Option<WriteReceipt>) -> Self {
        match receipt {
            Some(receipt) => {
                let reason = match receipt.validate() {
                    Err(_) => Some("receipt_invalid"),
                    Ok(()) => match receipt.require_reconciliation_envelope() {
                        Ok(_) => None,
                        Err(_) => Some("receipt_envelope_missing"),
                    },
                };
                match reason {
                    None => Self::Receipt {
                        receipt: Some(receipt),
                    },
                    Some(reason) => Self::Unknown {
                        operation_id: receipt.operation_id.clone(),
                        reason: reason.to_owned(),
                    },
                }
            }
            None => Self::Receipt { receipt: None },
        }
    }

    pub fn validate(&self) -> Result<(), StoreWireError> {
        match self {
            Self::Health { record } => record.validate().map_err(StoreWireError::Store),
            Self::Readiness { receipt } => receipt.validate(),
            Self::Named { response } => response.validate().map_err(StoreWireError::Store),
            Self::Transaction { receipt } => {
                receipt.validate().map_err(StoreWireError::Store)?;
                receipt
                    .require_reconciliation_envelope()
                    .map(|_| ())
                    .map_err(StoreWireError::Store)
            }
            Self::Receipt {
                receipt: Some(receipt),
            } => {
                receipt.validate().map_err(StoreWireError::Store)?;
                receipt
                    .require_reconciliation_envelope()
                    .map(|_| ())
                    .map_err(StoreWireError::Store)
            }
            Self::Receipt { receipt: None } => Ok(()),
            Self::RevisionHeads { heads } => {
                bounded_unique(heads, "revision_heads", |head| head.key.clone())?;
                for head in heads {
                    head.validate().map_err(StoreWireError::Store)?;
                }
                Ok(())
            }
            Self::OrderingHeads { heads } => {
                bounded_unique(heads, "ordering_heads", |head| head.scope.clone())?;
                for head in heads {
                    head.validate().map_err(StoreWireError::Store)?;
                }
                Ok(())
            }
            Self::Unknown { reason, .. } => validate_text(reason, "unknown.reason"),
            Self::Error { error } => validate_text(error, "error"),
        }
    }
}

/// Errors while validating or encoding the neutral store wire.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StoreWireError {
    #[error("store contract: {0}")]
    Store(StoreError),
    #[error("EBP protocol: {0}")]
    Protocol(String),
    #[error("EBP identity: {0}")]
    Identity(String),
    #[error("store wire payload: {0}")]
    Payload(String),
    #[error("store wire value: {0}")]
    Invalid(String),
    #[error("store response requires request correlation")]
    MissingCorrelation,
}

impl From<StoreError> for StoreWireError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Builds one authenticated Execute request frame.
pub fn request_frame(
    connection_id: impl Into<String>,
    protocol_version: ProtocolVersion,
    request_id: RequestId,
    identity: RequestIdentity,
    request: StoreRequest,
) -> Result<Frame, StoreWireError> {
    request.validate_for_identity(&request_id, &identity)?;
    let frame = Frame {
        protocol_version,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.into(),
        request_id: Some(request_id),
        kind: FrameKind::Request,
        message_type: MessageType::Execute,
        request_identity: Some(identity),
        payload: ProtocolPayload::Json(
            serde_json::to_value(request)
                .map_err(|error| StoreWireError::Payload(error.to_string()))?,
        ),
        trace_context: Default::default(),
    };
    frame
        .validate()
        .map_err(|error| StoreWireError::Protocol(error.to_string()))?;
    Ok(frame)
}

/// Decodes and validates one authenticated Execute request frame.
pub fn decode_request_frame(
    frame: &Frame,
) -> Result<(RequestId, RequestIdentity, StoreRequest), StoreWireError> {
    frame
        .validate()
        .map_err(|error| StoreWireError::Protocol(error.to_string()))?;
    if frame.encoding_profile != EncodingProfile::JsonV1
        || frame.kind != FrameKind::Request
        || frame.message_type != MessageType::Execute
    {
        return Err(StoreWireError::Invalid(
            "frame is not a json-v1 Request/Execute".to_owned(),
        ));
    }
    let request_id = frame
        .request_id
        .clone()
        .ok_or(StoreWireError::MissingCorrelation)?;
    let identity = frame
        .request_identity
        .clone()
        .ok_or_else(|| StoreWireError::Identity("request identity is required".to_owned()))?;
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err(StoreWireError::Invalid(
            "request payload must use json-v1".to_owned(),
        ));
    };
    let request: StoreRequest = serde_json::from_value(payload.clone())
        .map_err(|error| StoreWireError::Payload(error.to_string()))?;
    request.validate_for_identity(&request_id, &identity)?;
    Ok((request_id, identity, request))
}

/// Builds one correlated Result response frame.
pub fn response_frame(
    connection_id: impl Into<String>,
    protocol_version: ProtocolVersion,
    request_id: Option<RequestId>,
    response: StoreResponse,
) -> Result<Frame, StoreWireError> {
    response.validate()?;
    let request_id = request_id.ok_or(StoreWireError::MissingCorrelation)?;
    let frame = Frame {
        protocol_version,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.into(),
        request_id: Some(request_id),
        kind: FrameKind::Response,
        message_type: MessageType::Result,
        request_identity: None,
        payload: ProtocolPayload::Json(
            serde_json::to_value(response)
                .map_err(|error| StoreWireError::Payload(error.to_string()))?,
        ),
        trace_context: Default::default(),
    };
    frame
        .validate()
        .map_err(|error| StoreWireError::Protocol(error.to_string()))?;
    Ok(frame)
}

/// Decodes and validates one correlated Result response frame.
pub fn decode_response_frame(frame: &Frame) -> Result<(RequestId, StoreResponse), StoreWireError> {
    frame
        .validate()
        .map_err(|error| StoreWireError::Protocol(error.to_string()))?;
    if frame.encoding_profile != EncodingProfile::JsonV1
        || frame.kind != FrameKind::Response
        || frame.message_type != MessageType::Result
    {
        return Err(StoreWireError::Invalid(
            "frame is not a json-v1 Response/Result".to_owned(),
        ));
    }
    if frame.request_identity.is_some() {
        return Err(StoreWireError::Identity(
            "response must not carry request identity".to_owned(),
        ));
    }
    let request_id = frame
        .request_id
        .clone()
        .ok_or(StoreWireError::MissingCorrelation)?;
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err(StoreWireError::Invalid(
            "response payload must use json-v1".to_owned(),
        ));
    };
    let response: StoreResponse = serde_json::from_value(payload.clone())
        .map_err(|error| StoreWireError::Payload(error.to_string()))?;
    response.validate()?;
    Ok((request_id, response))
}

fn bounded_unique<T, I, F>(values: &[T], field: &'static str, key: F) -> Result<(), StoreError>
where
    I: Ord,
    F: Fn(&T) -> I,
{
    if values.len() > MAX_STORE_WIRE_ITEMS {
        return Err(StoreError::PayloadTooLarge);
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(key(value)) {
            return Err(StoreError::Duplicate { field });
        }
    }
    Ok(())
}

fn validate_optional_text(
    value: &Option<String>,
    field: &'static str,
) -> Result<(), StoreWireError> {
    if let Some(value) = value {
        validate_text(value, field)?;
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), StoreWireError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(StoreWireError::Invalid(format!(
            "{field} must be non-blank and contain no control characters"
        )));
    }
    Ok(())
}
