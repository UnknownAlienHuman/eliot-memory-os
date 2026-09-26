//! Governor-admission delivery gate for proposed learning deltas.
//!
//! Actor/Refiner may propose interpretation and next-behavior fields;
//! immutable attempt/evidence owners supply their references, and Governor
//! admission is required before any behavioral effect. A draft delta is
//! ineligible for retrieval, delivery, compilation, or use by another task.
//!
//! This module owns no admission minting (the Governor owns that in
//! `eliot-governor::learning_admission`); it only checks receipts at
//! delivery. A proposed interpretation may be stored, but it must not alter
//! route, context, tool use, search, verifier order, or overlay state until
//! admitted. This module deliberately does not import `eliot-governor` to
//! avoid a dependency cycle.

use eliot_contracts::ArtifactId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::LearningDeltaError;

/// Receipt proving Governor admission of one specific delta digest.
///
/// The receipt binds a delta identity to the exact digest the Governor
/// admitted. Any byte change to the delta invalidates the binding and the
/// delta must be re-admitted before delivery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReceipt {
    /// Governor-issued receipt handle (trimmed, non-empty, at most 256 chars).
    pub receipt_id: String,
    /// Identity of the admitted delta.
    pub delta_id: ArtifactId,
    /// Lowercase hex SHA-256 digest of the admitted delta bytes (64 chars).
    pub delta_digest: String,
}

impl AdmissionReceipt {
    /// Validate receipt shape without performing I/O or consulting the Governor.
    ///
    /// Returns `Ok(())` when the receipt handle is non-blank (at most 256
    /// chars), the delta id is non-blank, and the digest is 64 lowercase
    /// hex chars. Shape validity alone does not authorize delivery; callers
    /// must also check the id/digest binding via [`delivery_allowed`] or
    /// [`check_delivery`].
    pub fn validate(&self) -> Result<(), LearningDeltaError> {
        let trimmed = self.receipt_id.trim();
        if trimmed.is_empty() || self.receipt_id.len() > 256 {
            return Err(LearningDeltaError::InvalidInput {
                field: "admission.receipt",
            });
        }
        if self.delta_id.as_str().trim().is_empty() {
            return Err(LearningDeltaError::InvalidInput {
                field: "admission.delta",
            });
        }
        if self.delta_digest.len() != 64
            || !self
                .delta_digest
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(LearningDeltaError::InvalidInput {
                field: "admission.digest",
            });
        }
        Ok(())
    }
}

/// Typed reason the delivery gate refused one proposed behavioural change.
///
/// A refusal is a durable, comparable outcome rather than a bare `false`: a
/// consumer records *which* admission fact was missing or mismatched, so a
/// stale or mismatched receipt can never be silently reinterpreted as an
/// absent one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliveryRefusal {
    /// No admission receipt was presented for this delta.
    MissingReceipt,
    /// The presented receipt is malformed and proves nothing.
    InvalidReceipt,
    /// The receipt binds a different delta identity or digest.
    ReceiptMismatch,
}

/// Enforce the delivery gate and report the exact refusal reason.
///
/// Succeeds only when an admission receipt is present, validates, and binds
/// the exact delta identity and digest. Route, context, tool, search,
/// verifier-order, and overlay consumers must call this before applying any
/// `next_behavior_delta` effect: an unadmitted proposed behavioural change is
/// not delivered to the subsequent attempt.
pub fn check_delivery_typed(
    receipt: Option<&AdmissionReceipt>,
    delta_id: &ArtifactId,
    delta_digest: &str,
) -> Result<(), DeliveryRefusal> {
    let Some(receipt) = receipt else {
        return Err(DeliveryRefusal::MissingReceipt);
    };
    receipt
        .validate()
        .map_err(|_| DeliveryRefusal::InvalidReceipt)?;
    if receipt.delta_id != *delta_id || receipt.delta_digest != delta_digest {
        return Err(DeliveryRefusal::ReceiptMismatch);
    }
    Ok(())
}

/// Report whether a receipt authorizes delivery of the given delta.
///
/// Returns `false` when no receipt is present. When a receipt is present,
/// returns `true` only when the receipt validates and its delta id and
/// digest exactly match the candidate. Pure boolean check: no errors, no
/// I/O. An unadmitted proposed behavioral change is not delivered to the
/// subsequent attempt. Use [`check_delivery_typed`] when the refusal reason
/// must be recorded.
pub fn delivery_allowed(
    receipt: Option<&AdmissionReceipt>,
    delta_id: &ArtifactId,
    delta_digest: &str,
) -> bool {
    check_delivery_typed(receipt, delta_id, delta_digest).is_ok()
}

/// Enforce the delivery gate, returning an error when delivery is refused.
///
/// Succeeds exactly when [`check_delivery_typed`] succeeds; otherwise returns
/// `InvalidInput{field:"admission.delivery"}`.
pub fn check_delivery(
    receipt: Option<&AdmissionReceipt>,
    delta_id: &ArtifactId,
    delta_digest: &str,
) -> Result<(), LearningDeltaError> {
    check_delivery_typed(receipt, delta_id, delta_digest).map_err(|_| {
        LearningDeltaError::InvalidInput {
            field: "admission.delivery",
        }
    })
}

/// Filter candidate deltas down to the indices admitted by some receipt.
///
/// For each candidate `(delta_id, delta_digest)`, the index is deliverable
/// iff at least one receipt in `receipts` validates and matches that
/// candidate id and digest exactly. Used by the Context Compiler and overlay
/// activation to filter to admitted-only deltas.
pub fn select_deliverable_indices(
    candidates: &[(&ArtifactId, &str)],
    receipts: &[AdmissionReceipt],
) -> Vec<usize> {
    candidates
        .iter()
        .enumerate()
        .filter(|(_, (id, digest))| {
            receipts.iter().any(|receipt| {
                receipt.validate().is_ok()
                    && &receipt.delta_id == *id
                    && receipt.delta_digest == **digest
            })
        })
        .map(|(index, _)| index)
        .collect()
}
