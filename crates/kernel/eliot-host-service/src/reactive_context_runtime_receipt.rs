//! Bounded runtime-control receipt for one reactive Context delivery result.
//!
//! The durable delivery coordinator already returns a
//! [`ReactiveContextDeliveryReceipt`], but the Host runtime-control contract
//! has no typed projection for it. Callers therefore cannot distinguish an
//! exact delivery, an uncertain send, an explicit pre-send refusal, a replay,
//! or an already-settled operation without importing the whole Host queue
//! record.
//!
//! This module owns that missing projection only. It performs no delivery,
//! reads no queue, creates no acknowledgement and grants no Context authority.
//! A later wiring change can add the receipt to the runtime-control response
//! and stop discarding the coordinator result without changing the owner
//! semantics again.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_platform::PlatformHandle;
use eliot_protocol::ReactiveContextStage;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{DeliveryDisposition, ReactiveContextDeliveryReceipt};

/// Stable wire identity of the bounded Host reactive-delivery receipt.
pub const REACTIVE_CONTEXT_RUNTIME_RECEIPT_WIRE_ID: &str =
    "eliot.host.reactive-context-runtime-receipt.v1";
/// Current wire revision of the bounded Host reactive-delivery receipt.
pub const REACTIVE_CONTEXT_RUNTIME_RECEIPT_WIRE_VERSION: u16 = 1;

/// Closed runtime-control interpretation of one durable delivery result.
///
/// These values mirror [`DeliveryDisposition`] without serializing that
/// service-internal enum directly. No value implies recipient use, influence,
/// task completion, or canonical Context admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReactiveContextRuntimeDisposition {
    /// The event is durably queued but no send completed in this call.
    Queued,
    /// The exact event reached the admitted endpoint.
    Delivered,
    /// A send may have occurred, but the application result remains unknown.
    DeliveryUnknown,
    /// The transport owner proved that no delivery attempt was admitted.
    NotAttempted,
    /// The exact durable operation replayed without a second send.
    Replay,
    /// The durable operation already carries acknowledgement progress.
    AlreadyAcknowledged,
    /// The durable operation was already terminal when observed.
    AlreadyTerminal,
}

impl From<DeliveryDisposition> for ReactiveContextRuntimeDisposition {
    fn from(value: DeliveryDisposition) -> Self {
        match value {
            DeliveryDisposition::Queued => Self::Queued,
            DeliveryDisposition::Delivered => Self::Delivered,
            DeliveryDisposition::DeliveryUnknown => Self::DeliveryUnknown,
            DeliveryDisposition::NotAttempted => Self::NotAttempted,
            DeliveryDisposition::Replay => Self::Replay,
            DeliveryDisposition::AlreadyAcknowledged => Self::AlreadyAcknowledged,
            DeliveryDisposition::AlreadyTerminal => Self::AlreadyTerminal,
        }
    }
}

/// Bounded, digest-bound runtime receipt for one Host reactive Context
/// delivery observation.
///
/// The projection carries only stable identities and lifecycle facts already
/// retained by the Host queue. It deliberately omits the Context payload,
/// endpoint, free-text reason, owner receipt bytes and acknowledgement
/// evidence. `DELIVERED` means only the Host transport observation represented
/// by [`ReactiveContextRuntimeDisposition::Delivered`]; it is not recipient
/// acknowledgement or evidence of use.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextRuntimeReceipt {
    /// Stable wire identity.
    pub wire_id: String,
    /// Stable wire revision.
    pub wire_version: u16,
    /// Canonical durable queue operation identity.
    pub operation_id: PlatformHandle,
    /// Canonical idempotency identity of the same operation.
    pub idempotency_key: PlatformHandle,
    /// Canonical digest of the owner-produced reactive Context payload.
    pub payload_sha256: String,
    /// Durable queue lifecycle stage observed after the operation.
    pub stage: ReactiveContextStage,
    /// Bounded interpretation returned by the delivery coordinator.
    pub disposition: ReactiveContextRuntimeDisposition,
    /// Stable transport operation, when a send contour was established.
    pub transport_ref: Option<PlatformHandle>,
    /// Stable reconciliation operation, when the delivery result is unknown.
    pub reconciliation_ref: Option<PlatformHandle>,
    /// Queue generation that admitted the durable operation.
    pub queue_generation: u64,
    /// Host journal sequence of the last accepted mutation.
    pub last_mutation_sequence: u64,
    /// SHA-256 over every preceding receipt field.
    pub receipt_sha256: String,
}

#[derive(Serialize)]
struct ReactiveContextRuntimeReceiptMaterial<'a> {
    wire_id: &'a str,
    wire_version: u16,
    operation_id: &'a str,
    idempotency_key: &'a str,
    payload_sha256: &'a str,
    stage: ReactiveContextStage,
    disposition: ReactiveContextRuntimeDisposition,
    transport_ref: Option<&'a str>,
    reconciliation_ref: Option<&'a str>,
    queue_generation: u64,
    last_mutation_sequence: u64,
}

impl ReactiveContextRuntimeReceipt {
    fn material(&self) -> ReactiveContextRuntimeReceiptMaterial<'_> {
        ReactiveContextRuntimeReceiptMaterial {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            operation_id: self.operation_id.as_str(),
            idempotency_key: self.idempotency_key.as_str(),
            payload_sha256: &self.payload_sha256,
            stage: self.stage,
            disposition: self.disposition,
            transport_ref: self.transport_ref.as_ref().map(PlatformHandle::as_str),
            reconciliation_ref: self
                .reconciliation_ref
                .as_ref()
                .map(PlatformHandle::as_str),
            queue_generation: self.queue_generation,
            last_mutation_sequence: self.last_mutation_sequence,
        }
    }

    /// Computes the canonical digest of the receipt material.
    ///
    /// # Errors
    ///
    /// Returns [`ReactiveContextRuntimeReceiptError::Encoding`] when the
    /// bounded receipt material cannot be canonicalized.
    pub fn computed_digest(&self) -> Result<String, ReactiveContextRuntimeReceiptError> {
        let bytes = canonical_json_bytes(&self.material()).map_err(|error| {
            ReactiveContextRuntimeReceiptError::Encoding(error.to_string())
        })?;
        Ok(sha256_hex(&bytes))
    }

    /// Validates the closed shape and canonical digest.
    ///
    /// # Errors
    ///
    /// Returns [`ReactiveContextRuntimeReceiptError`] when a required identity,
    /// digest, sequence or wire value is malformed or the receipt digest does
    /// not bind the projected fields.
    pub fn validate(&self) -> Result<(), ReactiveContextRuntimeReceiptError> {
        if self.wire_id != REACTIVE_CONTEXT_RUNTIME_RECEIPT_WIRE_ID {
            return Err(ReactiveContextRuntimeReceiptError::InvalidField(
                "wire_id",
            ));
        }
        if self.wire_version != REACTIVE_CONTEXT_RUNTIME_RECEIPT_WIRE_VERSION {
            return Err(ReactiveContextRuntimeReceiptError::InvalidField(
                "wire_version",
            ));
        }
        validate_handle(&self.operation_id, "operation_id")?;
        validate_handle(&self.idempotency_key, "idempotency_key")?;
        validate_digest(&self.payload_sha256, "payload_sha256")?;
        if let Some(reference) = &self.transport_ref {
            validate_handle(reference, "transport_ref")?;
        }
        if let Some(reference) = &self.reconciliation_ref {
            validate_handle(reference, "reconciliation_ref")?;
        }
        if self.queue_generation == 0 {
            return Err(ReactiveContextRuntimeReceiptError::InvalidField(
                "queue_generation",
            ));
        }
        if self.last_mutation_sequence == 0 {
            return Err(ReactiveContextRuntimeReceiptError::InvalidField(
                "last_mutation_sequence",
            ));
        }
        validate_digest(&self.receipt_sha256, "receipt_sha256")?;
        if self.receipt_sha256 != self.computed_digest()? {
            return Err(ReactiveContextRuntimeReceiptError::DigestMismatch);
        }
        Ok(())
    }
}

/// Fail-closed errors produced by reactive runtime receipt projection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReactiveContextRuntimeReceiptError {
    /// A required identity, digest, sequence or wire value is malformed.
    #[error("REACTIVE_CONTEXT_RUNTIME_RECEIPT_INVALID:{0}")]
    InvalidField(&'static str),
    /// The bounded material could not be canonicalized.
    #[error("REACTIVE_CONTEXT_RUNTIME_RECEIPT_ENCODING:{0}")]
    Encoding(String),
    /// The receipt digest does not bind the projected fields.
    #[error("REACTIVE_CONTEXT_RUNTIME_RECEIPT_DIGEST_MISMATCH")]
    DigestMismatch,
}

/// Projects the complete service-internal delivery result into the bounded
/// runtime-control receipt.
///
/// This function is observational. It does not re-query the queue, retry a
/// send, interpret free-text failure reasons, or promote transport delivery to
/// recipient acknowledgement or Context use.
///
/// # Errors
///
/// Returns [`ReactiveContextRuntimeReceiptError`] when the durable result does
/// not contain well-formed stable identities or cannot produce a canonical
/// receipt digest.
pub fn project_reactive_context_runtime_receipt(
    source: &ReactiveContextDeliveryReceipt,
) -> Result<ReactiveContextRuntimeReceipt, ReactiveContextRuntimeReceiptError> {
    let mut receipt = ReactiveContextRuntimeReceipt {
        wire_id: REACTIVE_CONTEXT_RUNTIME_RECEIPT_WIRE_ID.to_owned(),
        wire_version: REACTIVE_CONTEXT_RUNTIME_RECEIPT_WIRE_VERSION,
        operation_id: source.entry.operation.operation_id.clone(),
        idempotency_key: source.entry.operation.idempotency_key.clone(),
        payload_sha256: source.entry.payload_sha256.clone(),
        stage: source.entry.stage,
        disposition: source.disposition.into(),
        transport_ref: source.entry.transport_ref.clone(),
        reconciliation_ref: source.entry.reconciliation_ref.clone(),
        queue_generation: source.entry.queue_generation,
        last_mutation_sequence: source.entry.last_mutation_sequence,
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = receipt.computed_digest()?;
    receipt.validate()?;
    Ok(receipt)
}

fn validate_handle(
    value: &PlatformHandle,
    field: &'static str,
) -> Result<(), ReactiveContextRuntimeReceiptError> {
    if value.as_str().trim().is_empty() || value.as_str().chars().any(char::is_control) {
        return Err(ReactiveContextRuntimeReceiptError::InvalidField(field));
    }
    Ok(())
}

fn validate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), ReactiveContextRuntimeReceiptError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ReactiveContextRuntimeReceiptError::InvalidField(field));
    }
    Ok(())
}
