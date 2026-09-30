//! Store-owned causal receipt projection for canonical source-artifact work.
//!
//! This module does not accept a causal binding from a request or receipt.
//! Callers first read the canonical fence and predecessor row from SurrealDB;
//! only that readback can construct the projection passed to the Store API.

use eliot_store_api::{
    CausalBinding, ReceiptId, StateFence, StoreError, TransactionSequence, WriteReceipt,
    committed_receipt_sequence,
};
use serde::Deserialize;

use crate::error::AdapterError;

/// One durable receipt row as projected by the canonical Store owner.
///
/// `commit_sequence` comes from the row's top-level Surreal field, while the
/// immutable receipt body is independently validated before its identity is
/// used as a causal predecessor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredReceiptHead {
    pub(crate) commit_sequence: u64,
    pub(crate) receipt: WriteReceipt,
}

/// Causal projection derived from a canonical allocation readback.
///
/// It remains crate-private and has no deserializer, so a wire caller cannot
/// supply the predecessor or sequence that the canonical database assigned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalCausalProjection {
    binding: CausalBinding,
    parent_receipt_id: Option<ReceiptId>,
    commit_sequence: u64,
}

impl CanonicalCausalProjection {
    /// Builds the binding for a commit sequence and its exact DB-owned tip.
    pub(crate) fn from_store_readback(
        state_fence: &StateFence,
        commit_sequence: u64,
        predecessor: Option<&StoredReceiptHead>,
    ) -> Result<Self, AdapterError> {
        state_fence
            .validate()
            .map_err(|_| AdapterError::Store(StoreError::InvalidReceipt))?;
        if commit_sequence == 0 {
            return Err(AdapterError::Store(StoreError::InvalidReceipt));
        }

        let parent_receipt_id = match (commit_sequence, predecessor) {
            (1, None) => None,
            (1, Some(_)) | (_, None) => {
                return Err(AdapterError::Store(StoreError::InvalidReceipt));
            }
            (sequence, Some(head)) if head.commit_sequence == sequence - 1 => {
                head.receipt.validate()?;
                let receipt_sequence = committed_receipt_sequence(&head.receipt)?;
                let envelope = head.receipt.require_reconciliation_envelope()?;
                let predecessor = envelope.core.causal.parent_receipt_id.clone();
                let expected_predecessors = predecessor.iter().cloned().collect::<Vec<_>>();
                if head.receipt.state_fence != envelope.core.causal.state_fence
                    || receipt_sequence != head.commit_sequence
                    || envelope.core.causal.transaction_sequence.value() != head.commit_sequence
                    || envelope.core.causal.predecessor_receipt_ids != expected_predecessors
                    || (head.commit_sequence == 1 && predecessor.is_some())
                    || (head.commit_sequence > 1 && predecessor.is_none())
                {
                    return Err(AdapterError::Store(StoreError::InvalidReceipt));
                }
                Some(
                    head.receipt
                        .require_reconciliation_envelope()?
                        .identity
                        .receipt_id
                        .clone(),
                )
            }
            _ => return Err(AdapterError::Store(StoreError::InvalidReceipt)),
        };

        let transaction_sequence = if commit_sequence == 1 {
            TransactionSequence::genesis()
        } else {
            TransactionSequence::new(commit_sequence)
                .map_err(|_| AdapterError::Store(StoreError::InvalidReceipt))?
        };
        let predecessor_receipt_ids = parent_receipt_id.iter().cloned().collect();
        let binding = CausalBinding {
            state_fence: state_fence.clone(),
            transaction_sequence,
            parent_receipt_id: parent_receipt_id.clone(),
            predecessor_receipt_ids,
        };
        Ok(Self {
            binding,
            parent_receipt_id,
            commit_sequence,
        })
    }

    pub(crate) fn binding(&self) -> &CausalBinding {
        &self.binding
    }

    pub(crate) fn commit_sequence(&self) -> u64 {
        self.commit_sequence
    }

    pub(crate) fn parent_receipt_id(&self) -> Option<&ReceiptId> {
        self.parent_receipt_id.as_ref()
    }
}
