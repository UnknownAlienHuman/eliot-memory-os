//! Bounded store-service payloads for the ELIOT Bridge Protocol.
//!
//! This module owns the semantic request/response catalogue.  The process
//! root owns only transport and handshake state; adapter SDKs, credentials,
//! query text, Blob bytes, lifecycle operations and maintenance services are
//! intentionally not representable here.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::RequestId;
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
    RequestIdentity,
    dreamer_job::{DurableJobRequest, DurableJobResponse},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CanonicalRequestView, CanonicalValidationSnapshot, ErasureIntentRecord, ErasureSurfaceKind,
    ExactJsonBytes, MAX_STORE_FAILURE_DETAIL_LEN, NamedReadRequest, NamedReadResponse, OperationId,
    OperationIdentity, OrderingHead, OrderingHeadExpectation, OrderingScopeId, PreparedTransition,
    RequestMeta, RevisionHead, RevisionHeadExpectation, RevisionKey, StoreError,
    StoreGenesisRequest, StoreHealth, StoreRecoveryRequest, StoreRecoverySnapshot, WriteReceipt,
    dreamer_job::map_durable_error, json_shape_name, verify_canonical_request_hash,
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
pub const CAPABILITY_VALIDATION_SNAPSHOT: &str = "store.validation_snapshot";
pub const CAPABILITY_RECOVERY: &str = "store.recovery";
pub const CAPABILITY_INITIALIZE_GENESIS: &str = "store.initialize_genesis";
/// Intent capability gate for neutral erasure dispatch (issue #688).
///
/// A store that cannot durably record intent must not advertise this
/// capability; a request selecting surfaces without this capability refuses
/// with zero destructive calls.
pub const CAPABILITY_ERASURE_INTENT: &str = "store.erasure.intent";
pub const CAPABILITY_DREAMER_JOB_SUBMIT: &str = "store.dreamer_job.submit";
pub const CAPABILITY_DREAMER_JOB_LEASE_NEXT: &str = "store.dreamer_job.lease_next";
pub const CAPABILITY_DREAMER_JOB_LEASE_EXACT: &str = "store.dreamer_job.lease_exact";
pub const CAPABILITY_DREAMER_JOB_RENEW: &str = "store.dreamer_job.renew";
pub const CAPABILITY_DREAMER_JOB_START: &str = "store.dreamer_job.start";
pub const CAPABILITY_DREAMER_JOB_CHECKPOINT: &str = "store.dreamer_job.checkpoint";
pub const CAPABILITY_DREAMER_JOB_RESUME: &str = "store.dreamer_job.resume";
pub const CAPABILITY_DREAMER_JOB_BEGIN_VERIFICATION: &str = "store.dreamer_job.begin_verification";
pub const CAPABILITY_DREAMER_JOB_PUBLISH: &str = "store.dreamer_job.publish";
pub const CAPABILITY_DREAMER_JOB_STATUS: &str = "store.dreamer_job.status";
pub const CAPABILITY_DREAMER_JOB_REQUEST_CANCEL: &str = "store.dreamer_job.request_cancel";
pub const CAPABILITY_DREAMER_JOB_RECONCILE: &str = "store.dreamer_job.reconcile";

/// Capabilities advertised by the canonical store process.
pub const CAPABILITIES: &[&str] = &[
    CAPABILITY_HEALTH,
    CAPABILITY_READINESS,
    CAPABILITY_NAMED_READ,
    CAPABILITY_APPLY,
    CAPABILITY_RECEIPT,
    CAPABILITY_REVISION_HEADS,
    CAPABILITY_ORDERING_HEADS,
    CAPABILITY_VALIDATION_SNAPSHOT,
    CAPABILITY_RECOVERY,
    CAPABILITY_INITIALIZE_GENESIS,
    CAPABILITY_DREAMER_JOB_SUBMIT,
    CAPABILITY_DREAMER_JOB_LEASE_NEXT,
    CAPABILITY_DREAMER_JOB_LEASE_EXACT,
    CAPABILITY_DREAMER_JOB_RENEW,
    CAPABILITY_DREAMER_JOB_START,
    CAPABILITY_DREAMER_JOB_CHECKPOINT,
    CAPABILITY_DREAMER_JOB_RESUME,
    CAPABILITY_DREAMER_JOB_BEGIN_VERIFICATION,
    CAPABILITY_DREAMER_JOB_PUBLISH,
    CAPABILITY_DREAMER_JOB_STATUS,
    CAPABILITY_DREAMER_JOB_REQUEST_CANCEL,
    CAPABILITY_DREAMER_JOB_RECONCILE,
];

/// Returns the exact per-operation capability for one closed Dreamer job
/// operation kind. The shared transport envelope is unchanged; only the
/// advertised capability varies per operation.
#[must_use]
pub fn dreamer_job_capability(
    operation: &eliot_protocol::dreamer_job::JobOperation,
) -> &'static str {
    use eliot_protocol::dreamer_job::JobOperation as Op;
    match operation {
        Op::Submit { .. } => CAPABILITY_DREAMER_JOB_SUBMIT,
        Op::LeaseNext { .. } => CAPABILITY_DREAMER_JOB_LEASE_NEXT,
        Op::LeaseExact { .. } => CAPABILITY_DREAMER_JOB_LEASE_EXACT,
        Op::Renew { .. } => CAPABILITY_DREAMER_JOB_RENEW,
        Op::Start { .. } => CAPABILITY_DREAMER_JOB_START,
        Op::Checkpoint { .. } => CAPABILITY_DREAMER_JOB_CHECKPOINT,
        Op::Resume { .. } => CAPABILITY_DREAMER_JOB_RESUME,
        Op::BeginVerification { .. } => CAPABILITY_DREAMER_JOB_BEGIN_VERIFICATION,
        Op::Publish { .. } => CAPABILITY_DREAMER_JOB_PUBLISH,
        Op::Status { .. } => CAPABILITY_DREAMER_JOB_STATUS,
        Op::RequestCancel { .. } => CAPABILITY_DREAMER_JOB_REQUEST_CANCEL,
        Op::Reconcile { .. } => CAPABILITY_DREAMER_JOB_RECONCILE,
    }
}

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
                validate_optional_text(self.expected_generation.as_deref(), "expected_generation")?;
                validate_optional_text(self.observed_generation.as_deref(), "observed_generation")?;
                if self.expected_generation.is_none() {
                    return Err(StoreWireError::Invalid(
                        "migration_required readiness needs expected_generation".to_owned(),
                    ));
                }
            }
            ReadinessStatus::Ready => {
                validate_optional_text(self.expected_generation.as_deref(), "expected_generation")?;
                validate_optional_text(self.observed_generation.as_deref(), "observed_generation")?;
                if self.expected_generation.is_none() || self.observed_generation.is_none() {
                    return Err(StoreWireError::Invalid(
                        "ready readiness needs both schema generations".to_owned(),
                    ));
                }
                if self.expected_generation != self.observed_generation {
                    return Err(StoreWireError::Invalid(
                        "ready readiness schema generations must match".to_owned(),
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
#[allow(clippy::large_enum_variant)]
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
    Recovery {
        request: StoreRecoveryRequest,
    },
    InitializeGenesis {
        context: RequestMeta,
        request: StoreGenesisRequest,
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
    ValidationSnapshot,
    DreamerJob {
        context: RequestMeta,
        request: DurableJobRequest,
    },
}

impl StoreRequest {
    /// Validates the closed operation and all bounded list fields.
    pub fn validate(&self) -> Result<(), StoreError> {
        match self {
            Self::Health | Self::Readiness | Self::Receipt { .. } | Self::ValidationSnapshot => {
                Ok(())
            }
            Self::Named { request } => request.validate(),
            Self::Recovery { request } => request.validate(),
            Self::InitializeGenesis { context, request } => {
                context.validate().map_err(StoreError::Foundation)?;
                request.validate()?;
                if context.state_fence != request.state_fence {
                    return Err(StoreError::FenceMismatch);
                }
                Ok(())
            }
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
            Self::RevisionHeads { keys } => bounded_unique(keys, "revision_keys", Clone::clone),
            Self::OrderingHeads { scopes } => {
                bounded_unique(scopes, "ordering_scopes", Clone::clone)
            }
            Self::DreamerJob { context, request } => {
                context.validate().map_err(StoreError::Foundation)?;
                request.validate().map_err(map_durable_error)?;
                if context.state_fence != request.request_identity.operation.state_fence {
                    return Err(StoreError::FenceMismatch);
                }
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn capability(&self) -> &'static str {
        match self {
            Self::Health => CAPABILITY_HEALTH,
            Self::Readiness => CAPABILITY_READINESS,
            Self::Named { .. } => CAPABILITY_NAMED_READ,
            Self::Apply { .. } => CAPABILITY_APPLY,
            Self::Receipt { .. } => CAPABILITY_RECEIPT,
            Self::RevisionHeads { .. } => CAPABILITY_REVISION_HEADS,
            Self::OrderingHeads { .. } => CAPABILITY_ORDERING_HEADS,
            Self::ValidationSnapshot => CAPABILITY_VALIDATION_SNAPSHOT,
            Self::Recovery { .. } => CAPABILITY_RECOVERY,
            Self::InitializeGenesis { .. } => CAPABILITY_INITIALIZE_GENESIS,
            Self::DreamerJob { request, .. } => dreamer_job_capability(&request.operation),
        }
    }

    /// Builds the shared canonical-request view for an `Apply` request.
    ///
    /// This rebinds the separately transported `context` and expected heads
    /// around the prepared transition (issue #63, RECHECK-63 slice A). The
    /// wire format is unchanged: every field is already transported, only
    /// reassembled here for the Kernel/store recompute path. Returns `None`
    /// for non-`Apply` variants, which carry no executable-request digest.
    #[must_use]
    pub fn apply_canonical_request_view(&self) -> Option<CanonicalRequestView> {
        match self {
            Self::Apply {
                context,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            } => Some(CanonicalRequestView::from_apply(
                context,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            )),
            _ => None,
        }
    }

    /// Recomputes the canonical request hash for an `Apply` request and
    /// rejects divergence with [`StoreError::TransitionDigestMismatch`].
    ///
    /// Non-`Apply` variants carry no executable-request digest and validate
    /// as `Ok`. Kernel/store call this before idempotency lookup and
    /// transaction so a separately transported load-bearing field cannot
    /// silently diverge from the admitted digest.
    pub fn verify_apply_canonical_hash(&self) -> Result<(), StoreError> {
        match self {
            Self::Apply { transition, .. } => match self.apply_canonical_request_view() {
                Some(view) => verify_canonical_request_hash(
                    &view,
                    &transition.identity.canonical_request_hash,
                ),
                None => Ok(()),
            },
            _ => Ok(()),
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
            Self::Recovery { request } if request.state_fence != identity.request.state_fence => {
                Err(StoreWireError::Identity(
                    "recovery request fence does not match request identity".to_owned(),
                ))
            }
            Self::InitializeGenesis { context, request } => {
                if context != &identity.request.metadata {
                    return Err(StoreWireError::Identity(
                        "genesis context does not match request identity metadata".to_owned(),
                    ));
                }
                if request.idempotency_key != identity.idempotency_key {
                    return Err(StoreWireError::Identity(
                        "genesis idempotency key does not match request identity".to_owned(),
                    ));
                }
                if request.state_fence != identity.request.state_fence {
                    return Err(StoreWireError::Identity(
                        "genesis request fence does not match request identity".to_owned(),
                    ));
                }
                Ok(())
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
            Self::DreamerJob { context, request } => {
                validate_dreamer_identity(context, request, identity)
            }
            _ => Ok(()),
        }
    }
}

fn validate_dreamer_identity(
    context: &RequestMeta,
    request: &DurableJobRequest,
    identity: &RequestIdentity,
) -> Result<(), StoreWireError> {
    if context != &identity.request.metadata {
        return Err(StoreWireError::Identity(
            "dreamer context does not match request identity metadata".to_owned(),
        ));
    }
    // Preserve the K0 stable-versus-fresh split: the K0 hash covers stable
    // mutation fields while the fresh transport correlation (`request_id`)
    // must still bind frame, outer identity, and inner K0 correlation.
    if request.request_identity.request.request.metadata != identity.request.metadata {
        return Err(StoreWireError::Identity(
            "dreamer request correlation does not match request identity metadata".to_owned(),
        ));
    }
    if request.request_identity.request.idempotency_key != identity.idempotency_key {
        return Err(StoreWireError::Identity(
            "dreamer transport idempotency key does not match request identity".to_owned(),
        ));
    }
    if request.request_identity.operation.state_fence != identity.request.state_fence
        || context.state_fence != identity.request.state_fence
    {
        return Err(StoreWireError::Identity(
            "dreamer request fence does not match request identity".to_owned(),
        ));
    }
    Ok(())
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
    ValidationSnapshot {
        snapshot: CanonicalValidationSnapshot,
    },
    Recovery {
        snapshot: StoreRecoverySnapshot,
    },
    Genesis {
        receipt: WriteReceipt,
    },
    DreamerJob {
        response: DurableJobResponse,
    },
    /// Typed provider-neutral failure introduced by the v2 failure contract.
    Failure {
        failure: crate::StoreFailure,
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
            Self::ValidationSnapshot { snapshot } => {
                snapshot.validate().map_err(StoreWireError::Store)
            }
            Self::Recovery { snapshot } => snapshot.validate().map_err(StoreWireError::Store),
            Self::DreamerJob { response } => response
                .validate()
                .map_err(|error| StoreWireError::Store(map_durable_error(error))),
            Self::Genesis { receipt } => {
                if receipt.transition_class != crate::TransitionClass::RecoverySchema {
                    return Err(StoreWireError::Store(StoreError::InvalidField {
                        field: "transition_class",
                        reason: "genesis receipt must use RecoverySchema",
                    }));
                }
                receipt.validate().map_err(StoreWireError::Store)?;
                receipt
                    .require_reconciliation_envelope()
                    .map(|_| ())
                    .map_err(StoreWireError::Store)
            }
            Self::Failure { failure } => failure
                .validate()
                .map_err(|error| StoreWireError::Invalid(error.to_string())),
            Self::Unknown { reason, .. } => validate_legacy_failure_text(reason, "unknown.reason"),
            Self::Error { error } => validate_legacy_failure_text(error, "error"),
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
        trace_context: BTreeMap::default(),
    };
    frame
        .validate()
        .map_err(|error| StoreWireError::Protocol(error.to_string()))?;
    Ok(frame)
}

/// Builds one authenticated Execute request frame with payload-authority
/// binding (issue #10, Wave B/C).
///
/// Each entry of `authorities` must be the [`ExactJsonBytes`] authority for
/// the named operation at the same index of an `Apply` transition: it is
/// revalidated and its decoded parameters must equal the operation's
/// queryable parameters byte-for-byte at the `Value` level. A mismatch is a
/// corrupt or substituted payload and fails closed here, before the `JsonV1`
/// codec can collapse anything.
///
/// The authorities travel inside the frame's `trace_context` under the
/// [`PAYLOAD_AUTHORITY_COUNT_KEY`] / [`payload_authority_entry_key`] channel
/// as exact JSON renderings of [`ExactJsonBytes`] (original raw bytes
/// preserved, never re-serialized from a collapsed `Value`). The `Frame`
/// struct and the `StoreRequest` wire shape are unchanged, so legacy ingress
/// that ignores `trace_context` keeps decoding; authority-aware ingress uses
/// [`decode_request_frame_with_authority`]. Any other request shape must
/// carry no authorities.
pub fn request_frame_with_payload_authority(
    connection_id: impl Into<String>,
    protocol_version: ProtocolVersion,
    request_id: RequestId,
    identity: RequestIdentity,
    request: StoreRequest,
    authorities: &[ExactJsonBytes],
) -> Result<Frame, StoreWireError> {
    bind_payload_authorities(&request, authorities)?;
    let mut frame = request_frame(
        connection_id,
        protocol_version,
        request_id,
        identity,
        request,
    )?;
    embed_payload_authorities(&mut frame, authorities)?;
    Ok(frame)
}

/// `trace_context` key carrying the number of embedded payload authorities.
///
/// The value is a decimal integer. `trace_context` stays a non-authoritative
/// transport map: every embedded authority is revalidated
/// ([`ExactJsonBytes::validate`]) and rebound to the decoded transition on
/// the decode path, so a tampered count or entry fails closed there.
const PAYLOAD_AUTHORITY_COUNT_KEY: &str = "eliot.store.payload_authority.count";

/// Renders the `trace_context` key for one embedded payload authority.
fn payload_authority_entry_key(index: usize) -> String {
    format!("eliot.store.payload_authority.{index}")
}

/// Embeds exact payload authorities into a frame's `trace_context`.
///
/// Each authority serializes through its canonical [`ExactJsonBytes`] shape,
/// which carries the original raw bytes opaquely; no authority is ever
/// reconstructed from a re-serialized `Value` here.
fn embed_payload_authorities(
    frame: &mut Frame,
    authorities: &[ExactJsonBytes],
) -> Result<(), StoreWireError> {
    for authority in authorities {
        authority.validate().map_err(StoreWireError::Store)?;
    }
    frame.trace_context.insert(
        PAYLOAD_AUTHORITY_COUNT_KEY.to_owned(),
        authorities.len().to_string(),
    );
    for (index, authority) in authorities.iter().enumerate() {
        let encoded = serde_json::to_string(authority)
            .map_err(|error| StoreWireError::Payload(error.to_string()))?;
        frame
            .trace_context
            .insert(payload_authority_entry_key(index), encoded);
    }
    Ok(())
}

/// Verifies that payload authorities exactly cover one `Apply` transition.
fn bind_payload_authorities(
    request: &StoreRequest,
    authorities: &[ExactJsonBytes],
) -> Result<(), StoreWireError> {
    match request {
        StoreRequest::Apply { transition, .. } => {
            if authorities.len() != transition.named_operations.len() {
                return Err(StoreWireError::Payload(
                    "payload authority count does not match named operations".to_owned(),
                ));
            }
            for (operation, authority) in transition.named_operations.iter().zip(authorities.iter())
            {
                authority.validate().map_err(StoreWireError::Store)?;
                let expected = authority
                    .decode_object_parameters()
                    .map_err(StoreWireError::Store)?;
                if expected != operation.parameters {
                    let shape = authority
                        .projection_value()
                        .map_or("undecodable", |value| json_shape_name(&value));
                    return Err(StoreWireError::Payload(format!(
                        "payload authority ({shape}) does not match named-operation parameters"
                    )));
                }
            }
            Ok(())
        }
        _ => {
            if authorities.is_empty() {
                Ok(())
            } else {
                Err(StoreWireError::Payload(
                    "payload authority requires an Apply transition".to_owned(),
                ))
            }
        }
    }
}

/// Decodes and validates one authenticated Execute request frame.
pub fn decode_request_frame(
    frame: &Frame,
) -> Result<(RequestId, RequestIdentity, StoreRequest), StoreWireError> {
    let (request_id, identity, request, _) = decode_request_frame_with_authority(frame)?;
    Ok((request_id, identity, request))
}

/// Decodes and validates one authenticated Execute request frame while
/// preserving its embedded payload authorities (slice C2, issue #19).
///
/// The returned authorities carry the original raw bytes exactly as embedded
/// by [`request_frame_with_payload_authority`]: each entry is deserialized
/// from the frame channel and revalidated ([`ExactJsonBytes::validate`]), so
/// its digest still binds version, encoding and the original bytes. Frames
/// without the authority channel yield an empty vector and take the legacy
/// path downstream. When authorities are present they are rebound to the
/// decoded transition here, before any staging or commit: a count mismatch,
/// a missing or trailing entry, a digest failure, or a parameter mismatch is
/// a corrupt or substituted payload and fails closed without fallback.
pub fn decode_request_frame_with_authority(
    frame: &Frame,
) -> Result<
    (
        RequestId,
        RequestIdentity,
        StoreRequest,
        Vec<ExactJsonBytes>,
    ),
    StoreWireError,
> {
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
    let authorities = extract_payload_authorities(frame, &request)?;
    Ok((request_id, identity, request, authorities))
}

/// Recovers embedded payload authorities from a decoded frame.
///
/// The channel is strict: a missing count with no entries means legacy
/// (empty vector); a missing count with entries, an unparsable count, a
/// missing or trailing entry, a malformed authority, a digest failure, or a
/// parameter mismatch all fail closed as payload errors.
fn extract_payload_authorities(
    frame: &Frame,
    request: &StoreRequest,
) -> Result<Vec<ExactJsonBytes>, StoreWireError> {
    let Some(count_text) = frame.trace_context.get(PAYLOAD_AUTHORITY_COUNT_KEY) else {
        for key in frame.trace_context.keys() {
            if key.starts_with("eliot.store.payload_authority.") {
                return Err(StoreWireError::Payload(
                    "payload authority entries without an authority count".to_owned(),
                ));
            }
        }
        return Ok(Vec::new());
    };
    let count: usize = count_text.parse().map_err(|_| {
        StoreWireError::Payload("payload authority count is not a decimal integer".to_owned())
    })?;
    let mut authorities = Vec::with_capacity(count);
    for index in 0..count {
        let key = payload_authority_entry_key(index);
        let encoded = frame.trace_context.get(&key).ok_or_else(|| {
            StoreWireError::Payload(format!(
                "payload authority entry is missing for operation {index}"
            ))
        })?;
        let authority: ExactJsonBytes = serde_json::from_str(encoded)
            .map_err(|error| StoreWireError::Payload(error.to_string()))?;
        authority.validate().map_err(StoreWireError::Store)?;
        authorities.push(authority);
    }
    for key in frame.trace_context.keys() {
        if key.starts_with("eliot.store.payload_authority.")
            && key != PAYLOAD_AUTHORITY_COUNT_KEY
            && !key
                .strip_prefix("eliot.store.payload_authority.")
                .is_some_and(|suffix| {
                    suffix
                        .parse::<usize>()
                        .is_ok_and(|index| index < count && suffix == index.to_string())
                })
        {
            return Err(StoreWireError::Payload(
                "trailing payload authority entry beyond the authority count".to_owned(),
            ));
        }
    }
    bind_payload_authorities(request, &authorities)?;
    Ok(authorities)
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
        trace_context: BTreeMap::default(),
    };
    frame
        .validate()
        .map_err(|error| StoreWireError::Protocol(error.to_string()))?;
    Ok(frame)
}

/// Decodes and validates one correlated Result response frame bound to the
/// already authenticated EBP session.
///
/// Response shape validation alone is not sufficient for an Apply: a frame
/// from another connection or protocol epoch must remain an unknown outcome
/// for the exact operation rather than being accepted as a response.
pub fn decode_response_frame(
    frame: &Frame,
    expected_connection_id: &str,
    expected_protocol: ProtocolVersion,
) -> Result<(RequestId, StoreResponse), StoreWireError> {
    frame
        .validate()
        .map_err(|error| StoreWireError::Protocol(error.to_string()))?;
    if frame.connection_id != expected_connection_id {
        return Err(StoreWireError::Identity(
            "response connection_id does not match the authenticated session".to_owned(),
        ));
    }
    if frame.protocol_version != expected_protocol {
        return Err(StoreWireError::Protocol(
            "response protocol does not match the negotiated session".to_owned(),
        ));
    }
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

fn validate_optional_text(value: Option<&str>, field: &'static str) -> Result<(), StoreWireError> {
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

/// Closed neutral erasure dispatch wrapper (issue #688).
///
/// Carries operation identity, the durable [`ErasureIntentRecord`] recorded
/// before dispatch, and the selected surfaces in deterministic canonical
/// order. `validate` runs before any destructive call: the intent must
/// validate, the selected surfaces must exactly equal the intent's planned
/// surfaces in canonical order, and the store must advertise
/// [`CAPABILITY_ERASURE_INTENT`]. A request without that intent capability
/// refuses with [`StoreError::UnknownOperation`] and zero destructive calls.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureSurfaceRequest {
    pub identity: OperationIdentity,
    pub intent: ErasureIntentRecord,
    pub surfaces: Vec<ErasureSurfaceKind>,
}

impl ErasureSurfaceRequest {
    /// Returns the exact capability required to dispatch this request.
    #[must_use]
    pub const fn required_capability() -> &'static str {
        CAPABILITY_ERASURE_INTENT
    }

    /// Validates identity, intent and selected surfaces before dispatch.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_erasure_surface_request(self, true)
    }

    /// Validates the request and refuses when the intent capability is absent.
    ///
    /// Pass the store's advertised capabilities: dispatch proceeds only when
    /// they contain [`CAPABILITY_ERASURE_INTENT`]. A missing capability
    /// refuses with [`StoreError::UnknownOperation`] and zero destructive
    /// calls; it never falls back to a degraded dispatch.
    pub fn validate_for_dispatch(&self, advertised: &[&str]) -> Result<(), StoreError> {
        validate_erasure_surface_request(self, advertised.contains(&CAPABILITY_ERASURE_INTENT))
    }

    /// Binds the decoded request to the authenticated EBP identity.
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
        if self.identity.idempotency_key != identity.idempotency_key {
            return Err(StoreWireError::Identity(
                "erasure idempotency key does not match request identity".to_owned(),
            ));
        }
        if self.intent.state_fence != identity.request.state_fence {
            return Err(StoreWireError::Identity(
                "erasure intent fence does not match request identity".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Validates one closed erasure wrapper and its intent capability.
///
/// Shared by [`ErasureSurfaceRequest::validate`] (capability assumed present
/// at the validation stage) and
/// [`ErasureSurfaceRequest::validate_for_dispatch`] (capability checked
/// against the advertised set).
fn validate_erasure_surface_request(
    request: &ErasureSurfaceRequest,
    intent_capability: bool,
) -> Result<(), StoreError> {
    request.identity.validate()?;
    request.intent.validate()?;
    if request.identity.operation_id != request.intent.operation_id
        || request.identity.canonical_request_hash != request.intent.request_digest
    {
        return Err(StoreError::IdentityConflict);
    }
    if request.surfaces.is_empty() {
        return Err(StoreError::Empty {
            field: "erasure.surfaces",
        });
    }
    if request.surfaces != request.intent.surfaces {
        return Err(StoreError::InvalidField {
            field: "erasure.surfaces",
            reason: "selected surfaces must exactly equal the recorded intent plan",
        });
    }
    if !intent_capability {
        return Err(StoreError::UnknownOperation);
    }
    Ok(())
}

fn validate_legacy_failure_text(value: &str, field: &'static str) -> Result<(), StoreWireError> {
    if value.len() > MAX_STORE_FAILURE_DETAIL_LEN {
        return Err(StoreWireError::Invalid(format!(
            "{field} exceeds the bounded legacy detail limit"
        )));
    }
    validate_text(value, field)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::{
        EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
        OperationIdentity, OperationManifestDigest, OrderingScopeId, PayloadSource,
        PreparedTransition, ScopeId, SecurityContext, TransitionClass,
    };
    use serde_json::{Value, json};
    use std::collections::BTreeMap;

    fn test_fence() -> crate::StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero")).expect("epoch");
        crate::StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn test_context(fence: &crate::StateFence) -> crate::RequestMeta {
        crate::RequestMeta {
            request_id: RequestId::new("request-authority").expect("request id"),
            session_id: None,
            task_id: None,
            product_id: eliot_contracts::ProductId::new("product-authority").expect("product id"),
            source_id: eliot_contracts::SourceId::new("source-authority").expect("source id"),
            state_fence: fence.clone(),
            clock: eliot_contracts::ClockReading::default(),
        }
    }

    fn apply_parts(params: BTreeMap<String, Value>) -> (crate::RequestMeta, PreparedTransition) {
        let fence = test_fence();
        let context = test_context(&fence);
        let transition = PreparedTransition {
            identity: OperationIdentity {
                operation_id: OperationId::new("op-authority").expect("operation id"),
                idempotency_key: "idem-authority".to_owned(),
                canonical_request_hash: "a".repeat(64),
            },
            state_fence: fence,
            scope_id: ScopeId::new("scope-authority").expect("scope"),
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope-authority").expect("ordering")],
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: "b".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("manifest-authority")
                .expect("manifest digest"),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::CaptureObservation,
                parameters: params,
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        };
        (context, transition)
    }

    fn test_identity(context: &crate::RequestMeta, idempotency_key: &str) -> RequestIdentity {
        RequestIdentity {
            request: eliot_receipts::RequestBinding {
                metadata: context.clone(),
                state_fence: context.state_fence.clone(),
            },
            idempotency_key: idempotency_key.to_owned(),
            deadline_unix_ms: 1,
            cancellation_id: "cancel-authority".to_owned(),
        }
    }

    fn apply_frame(
        context: &crate::RequestMeta,
        transition: PreparedTransition,
        authorities: &[ExactJsonBytes],
    ) -> Frame {
        request_frame_with_payload_authority(
            "connection-authority",
            ProtocolVersion::CURRENT,
            context.request_id.clone(),
            test_identity(context, &transition.identity.idempotency_key),
            StoreRequest::Apply {
                context: context.clone(),
                transition,
                expected_revision_heads: Vec::new(),
                expected_ordering_heads: Vec::new(),
            },
            authorities,
        )
        .expect("authority frame builds")
    }

    #[test]
    fn advertised_capabilities_are_complete_unique_and_canonical() {
        const EXPECTED: &[&str] = &[
            CAPABILITY_HEALTH,
            CAPABILITY_READINESS,
            CAPABILITY_NAMED_READ,
            CAPABILITY_APPLY,
            CAPABILITY_RECEIPT,
            CAPABILITY_REVISION_HEADS,
            CAPABILITY_ORDERING_HEADS,
            CAPABILITY_VALIDATION_SNAPSHOT,
            CAPABILITY_RECOVERY,
            CAPABILITY_INITIALIZE_GENESIS,
            CAPABILITY_DREAMER_JOB_SUBMIT,
            CAPABILITY_DREAMER_JOB_LEASE_NEXT,
            CAPABILITY_DREAMER_JOB_LEASE_EXACT,
            CAPABILITY_DREAMER_JOB_RENEW,
            CAPABILITY_DREAMER_JOB_START,
            CAPABILITY_DREAMER_JOB_CHECKPOINT,
            CAPABILITY_DREAMER_JOB_RESUME,
            CAPABILITY_DREAMER_JOB_BEGIN_VERIFICATION,
            CAPABILITY_DREAMER_JOB_PUBLISH,
            CAPABILITY_DREAMER_JOB_STATUS,
            CAPABILITY_DREAMER_JOB_REQUEST_CANCEL,
            CAPABILITY_DREAMER_JOB_RECONCILE,
        ];

        assert_eq!(CAPABILITIES, EXPECTED);
        assert!(CAPABILITIES
            .iter()
            .all(|capability| capability.starts_with("store.") && !capability.trim().is_empty()));

        let unique: BTreeSet<&str> = CAPABILITIES.iter().copied().collect();
        assert_eq!(unique.len(), CAPABILITIES.len());
    }

    #[test]
    fn authority_frame_round_trip_preserves_original_raw_bytes() {
        let raw = br#"{"subject":"observation-1"}"#;
        let authority = ExactJsonBytes::parse(PayloadSource::NamedOperationParameter, raw)
            .expect("authority parses");
        let (context, transition) =
            apply_parts(authority.decode_object_parameters().expect("params"));
        let frame = apply_frame(&context, transition, std::slice::from_ref(&authority));
        let (_, _, request, recovered) =
            decode_request_frame_with_authority(&frame).expect("authority frame decodes");
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].bytes, raw);
        assert_eq!(recovered[0].digest_hex(), authority.digest_hex());
        let StoreRequest::Apply { transition, .. } = request else {
            panic!("apply request round-trips");
        };
        assert_eq!(
            recovered[0]
                .decode_object_parameters()
                .expect("authority decodes"),
            transition.named_operations[0].parameters
        );
    }

    #[test]
    fn authority_keeps_null_absent_false_and_zero_distinct() {
        // One owner-shaped parameter field carrying the four JSON spellings
        // that a collapsed `Value` pipeline must never conflate. The
        // authority layer keeps them distinct as opaque bytes and as decoded
        // values; the generic transition validator still rejects an explicit
        // null (C1-owned `validate_parameters` rule, frozen for this slice),
        // so only the three `Value`-valid spellings take the frame path here.
        let raws: [&[u8]; 4] = [
            br#"{"subject":null}"#,
            b"{}",
            br#"{"subject":false}"#,
            br#"{"subject":0}"#,
        ];
        let authorities: Vec<ExactJsonBytes> = raws
            .iter()
            .map(|raw| {
                ExactJsonBytes::parse(PayloadSource::NamedOperationParameter, raw)
                    .expect("variant parses")
            })
            .collect();
        let digests: BTreeSet<String> =
            authorities.iter().map(ExactJsonBytes::digest_hex).collect();
        assert_eq!(digests.len(), 4, "all four spellings bind distinct digests");
        let decoded: Vec<BTreeMap<String, Value>> = authorities
            .iter()
            .map(|authority| {
                authority
                    .decode_object_parameters()
                    .expect("variant decodes")
            })
            .collect();
        for (left, right) in decoded.iter().zip(decoded.iter().skip(1)) {
            assert_ne!(left, right, "decoded parameters stay distinct");
        }
        // Cross-binding any authority against another variant's parameters
        // fails closed instead of substituting the payload.
        let (context, transition) = apply_parts(decoded[2].clone());
        assert!(
            request_frame_with_payload_authority(
                "connection-authority",
                ProtocolVersion::CURRENT,
                context.request_id.clone(),
                test_identity(&context, &transition.identity.idempotency_key),
                StoreRequest::Apply {
                    context: context.clone(),
                    transition,
                    expected_revision_heads: Vec::new(),
                    expected_ordering_heads: Vec::new(),
                },
                &[authorities[0].clone()],
            )
            .is_err(),
            "null authority must not bind false parameters"
        );
        // The three `Value`-valid spellings round-trip byte-identically
        // through a genuine frame encode/decode.
        for (raw, params) in [raws[1], raws[2], raws[3]].into_iter().zip([
            decoded[1].clone(),
            decoded[2].clone(),
            decoded[3].clone(),
        ]) {
            let authority = ExactJsonBytes::parse(PayloadSource::NamedOperationParameter, raw)
                .expect("variant parses");
            let (context, transition) = apply_parts(params);
            let frame = apply_frame(&context, transition, &[authority]);
            let (_, _, _, recovered) =
                decode_request_frame_with_authority(&frame).expect("variant frame decodes");
            assert_eq!(recovered.len(), 1);
            assert_eq!(recovered[0].bytes, raw);
        }
        // The explicit-null spelling still fails closed at the generic
        // parameter boundary before any frame is produced.
        let (context, transition) = apply_parts(decoded[0].clone());
        assert!(
            request_frame_with_payload_authority(
                "connection-authority",
                ProtocolVersion::CURRENT,
                context.request_id.clone(),
                test_identity(&context, &transition.identity.idempotency_key),
                StoreRequest::Apply {
                    context: context.clone(),
                    transition,
                    expected_revision_heads: Vec::new(),
                    expected_ordering_heads: Vec::new(),
                },
                &[authorities[0].clone()],
            )
            .is_err(),
            "explicit null still rejected by the frozen generic parameter rule"
        );
    }

    #[test]
    fn legacy_frames_decode_without_authorities_and_tampering_fails_closed() {
        let (context, transition) = apply_parts(BTreeMap::from([(
            "subject".to_owned(),
            json!("observation-1"),
        )]));
        let frame = request_frame(
            "connection-authority",
            ProtocolVersion::CURRENT,
            context.request_id.clone(),
            test_identity(&context, &transition.identity.idempotency_key),
            StoreRequest::Apply {
                context: context.clone(),
                transition,
                expected_revision_heads: Vec::new(),
                expected_ordering_heads: Vec::new(),
            },
        )
        .expect("legacy frame builds");
        let (_, _, _, recovered) =
            decode_request_frame_with_authority(&frame).expect("legacy frame decodes");
        assert!(recovered.is_empty(), "legacy frames take the legacy path");

        // Entries without a count fail closed.
        let mut orphan = frame.clone();
        orphan.trace_context.insert(
            payload_authority_entry_key(0),
            json!({"version": 1}).to_string(),
        );
        assert!(decode_request_frame_with_authority(&orphan).is_err());

        // A count without its entry fails closed.
        let mut missing = frame.clone();
        missing
            .trace_context
            .insert(PAYLOAD_AUTHORITY_COUNT_KEY.to_owned(), "1".to_owned());
        assert!(decode_request_frame_with_authority(&missing).is_err());

        // A trailing entry beyond the count fails closed.
        let raw = br#"{"subject":"observation-1"}"#;
        let authority = ExactJsonBytes::parse(PayloadSource::NamedOperationParameter, raw)
            .expect("authority parses");
        let (context, transition) =
            apply_parts(authority.decode_object_parameters().expect("params"));
        let mut trailing = apply_frame(&context, transition, &[authority]);
        trailing.trace_context.insert(
            payload_authority_entry_key(1),
            json!({"version": 1}).to_string(),
        );
        assert!(decode_request_frame_with_authority(&trailing).is_err());

        // A substituted digest fails closed.
        let mut substituted = apply_frame(
            &context,
            apply_parts(BTreeMap::from([(
                "subject".to_owned(),
                json!("observation-1"),
            )]))
            .1,
            &[
                ExactJsonBytes::parse(PayloadSource::NamedOperationParameter, raw)
                    .expect("authority parses"),
            ],
        );
        let mut tampered: ExactJsonBytes =
            serde_json::from_str(&substituted.trace_context[&payload_authority_entry_key(0)])
                .expect("embedded authority parses");
        tampered.bytes = br#"{"subject":"substituted"}"#.to_vec();
        substituted.trace_context.insert(
            payload_authority_entry_key(0),
            serde_json::to_string(&tampered).expect("tampered authority encodes"),
        );
        assert!(decode_request_frame_with_authority(&substituted).is_err());
    }

    #[test]
    fn apply_canonical_hash_verifies_the_recomputed_digest() {
        use crate::{OrderingHeadExpectation, RevisionHeadExpectation};
        let (context, mut transition) = apply_parts(BTreeMap::from([(
            "subject".to_owned(),
            json!("observation-1"),
        )]));
        let fence = context.state_fence.clone();
        let revision_heads = vec![RevisionHeadExpectation {
            key: crate::RevisionKey::new("scope:one").expect("key"),
            expected_revision: 1,
            state_fence: fence.clone(),
        }];
        let ordering_heads = vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new("scope-authority").expect("ordering"),
            expected_sequence: 1,
            state_fence: fence,
        }];
        // The placeholder digest diverges from the recomputed request hash.
        let stale = StoreRequest::Apply {
            context: context.clone(),
            transition: transition.clone(),
            expected_revision_heads: revision_heads.clone(),
            expected_ordering_heads: ordering_heads.clone(),
        };
        assert!(matches!(
            stale.verify_apply_canonical_hash(),
            Err(crate::StoreError::TransitionDigestMismatch { .. })
        ));
        // The recomputed digest verifies; non-apply variants carry no digest.
        let view = stale
            .apply_canonical_request_view()
            .expect("apply view builds");
        transition.identity.canonical_request_hash =
            crate::canonical_request_hash(&view).expect("digest computes");
        let fresh = StoreRequest::Apply {
            context,
            transition,
            expected_revision_heads: revision_heads,
            expected_ordering_heads: ordering_heads,
        };
        assert!(fresh.verify_apply_canonical_hash().is_ok());
        assert!(StoreRequest::Health.verify_apply_canonical_hash().is_ok());
    }
}
