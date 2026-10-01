//! Kernel-owned read route for durable mailbox messages.
//!
//! Serves the admitted mailbox view over the retained store rows. The caller
//! issues [`mailbox_message_read_request`] as the exact-identity
//! `GetMailboxMessage` named read, the store bridge answers it from the W1c
//! identity row, and [`serve_mailbox_message_read`] decodes that retained row
//! back through the admitted view ([`read_mailbox_message`]).
//!
//! This route stores nothing, admits nothing, and interprets nothing beyond
//! identity: every retained agreement failure (wrong operation, absent or
//! malformed payload, failed record validation, fence or identity mismatch)
//! is a typed [`CoordinationMailboxError`] refusal, never a repaired view.
//! There is no second store, scheduler, table, or key design here; the row
//! address is the W1c identity key the store legs already own.
//!
//! # Relation to the write path
//!
//! Admission stays where W1c/W1d put it: the Kernel admits through
//! `admit_mailbox_message`, the store persists through
//! `AdmitMailboxMessage`. This file is only the read leg that makes those
//! retained rows readable through the admitted view.

use std::collections::BTreeMap;

use eliot_store_api::{
    MailboxItemRecord, NamedReadOperation, NamedReadRequest, NamedReadResponse, ReadConsistency,
    ScopeId, StateFence,
};
use serde_json::Value;

use super::coordination_mailbox::{
    CoordinationMailboxError, CoordinationMailboxRecord, MAX_IDENTITY_LEN, read_mailbox_message,
};

/// Builds the exact-identity `GetMailboxMessage` read request for one
/// message.
///
/// Mirrors the store `blackboard_item_read_request` precedent: no scope,
/// `ExactFence` consistency, and the single identity selector. The store
/// mailbox surface owns no read-request builder of its own, so the Kernel
/// read route carries this constructor rather than a second copy of the
/// selector contract.
pub(crate) fn mailbox_message_read_request(
    message_id: &str,
    state_fence: &StateFence,
) -> Result<NamedReadRequest, CoordinationMailboxError> {
    require_message_id(message_id)?;
    state_fence
        .validate()
        .map_err(CoordinationMailboxError::Foundation)?;
    let parameters =
        BTreeMap::from([("message_id".to_owned(), Value::String(message_id.to_owned()))]);
    Ok(NamedReadRequest {
        operation: NamedReadOperation::GetMailboxMessage,
        scope_id: None::<ScopeId>,
        consistency: ReadConsistency::ExactFence,
        state_fence: state_fence.clone(),
        parameters,
    })
}

/// Serves the admitted mailbox view over the retained rows of one
/// `GetMailboxMessage` read response.
///
/// The retained [`MailboxItemRecord`] is decoded, validated, fence- and
/// identity-bound exactly as the store readback proved it, converted
/// field-for-field into the admitted record shape, and served through
/// [`read_mailbox_message`] over that retained row: the view function stays
/// the single interpreter of the admitted view, and this route only proves
/// the row it serves.
pub(crate) fn serve_mailbox_message_read(
    response: &NamedReadResponse,
    message_id: &str,
) -> Result<CoordinationMailboxRecord, CoordinationMailboxError> {
    require_message_id(message_id)?;
    if response.operation != NamedReadOperation::GetMailboxMessage {
        return Err(CoordinationMailboxError::InvalidField {
            field: "mailbox.operation",
            reason: "response is not a mailbox message read",
        });
    }
    if response.payload.is_null() {
        return Err(CoordinationMailboxError::NotFound {
            message_id: message_id.to_owned(),
        });
    }
    let retained: MailboxItemRecord = serde_json::from_value(response.payload.clone()).map_err(|_| {
        CoordinationMailboxError::InvalidField {
            field: "mailbox.record",
            reason: "retained row is not a mailbox message",
        }
    })?;
    retained
        .validate()
        .map_err(|_| CoordinationMailboxError::InvalidField {
            field: "mailbox.record",
            reason: "retained row failed validation",
        })?;
    if retained.state_fence != response.state_fence {
        return Err(CoordinationMailboxError::InvalidField {
            field: "mailbox.state_fence",
            reason: "retained row fence disagrees with the read fence",
        });
    }
    if retained.message_id != message_id {
        return Err(CoordinationMailboxError::NotFound {
            message_id: message_id.to_owned(),
        });
    }
    let record = CoordinationMailboxRecord {
        message_id: retained.message_id,
        recipient_id: retained.recipient_id,
        task_id: retained.task_id,
        sender_principal: retained.sender_principal,
        submitter_principal: retained.submitter_principal,
        provenance: retained.provenance,
        privacy_class: retained.privacy_class,
        disclosure: retained.disclosure,
        body: retained.body,
        requires_acknowledgement: retained.requires_acknowledgement,
        state_fence: retained.state_fence,
        submitted_at_unix_ms: retained.submitted_at_unix_ms,
        sequence: retained.sequence,
    };
    let retained = [record];
    Ok(read_mailbox_message(&retained, message_id)?.clone())
}

/// Requires the bounded, non-blank message identity the admitted view reads
/// by, mirroring the admission text rule plus its length bound.
fn require_message_id(message_id: &str) -> Result<(), CoordinationMailboxError> {
    if message_id.trim().is_empty() || message_id.chars().any(char::is_control) {
        return Err(CoordinationMailboxError::InvalidField {
            field: "message_id",
            reason: "blank or control character",
        });
    }
    if message_id.len() > MAX_IDENTITY_LEN {
        return Err(CoordinationMailboxError::InvalidField {
            field: "message_id",
            reason: "exceeds admission bound",
        });
    }
    Ok(())
}
