//! Durable owner for authenticated-session ExternalAttach receipts (#1782).
//!
//! Rows are immutable and indexed by the exact Kernel server session binding.
//! Session pages pin the index revision and row count; an append during a walk
//! returns a typed movement error, so callers cannot clear a gate from a torn
//! or incomplete set. Backup treats this table as historical evidence and never
//! restores an old OS session as live authority (A13.7).

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use redb::{ReadableDatabase, ReadableTable};
use serde::{Deserialize, Serialize};

use crate::{OperationIdentity, OperationalMutationReceipt, OperationalPhase, OrsError};

const RECORD_SCHEMA_VERSION: u16 = 1;
const SESSION_INDEX_PREFIX: &str = "external_attach_session_index_v1:";
const MAX_DIGEST_LENGTH: usize = 64;

/// Exact immutable ExternalAttach receipt supplied by the authenticated
/// Kernel caller. The owner stores the exact bytes and digest unchanged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAttachReceiptWrite {
    pub key: OperationIdentity,
    pub owner_session_binding: String,
    pub state_fence: StateFence,
    pub canonical_payload: String,
    pub payload_sha256: String,
}

/// Exact-key lookup under the authenticated Kernel server session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAttachReceiptRead {
    pub key: OperationIdentity,
    pub owner_session_binding: String,
    pub state_fence: StateFence,
}

/// Owner-emitted continuation for one pinned session receipt set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAttachReceiptCursor {
    pub session_revision: u64,
    pub after_key: Option<OperationIdentity>,
    pub emitted_rows: u64,
}

/// Paginated read selector for all receipts in one authenticated OS session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAttachReceiptSessionRead {
    pub owner_session_binding: String,
    pub expected_state_fence: StateFence,
    pub cursor: Option<ExternalAttachReceiptCursor>,
    pub limit: u16,
}

/// Store-issued integrity receipt and exact owner row readback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAttachReceiptReadback {
    pub key: OperationIdentity,
    pub owner_session_binding: String,
    pub state_fence: StateFence,
    pub canonical_payload: String,
    pub payload_sha256: String,
    pub store_receipt: OperationalMutationReceipt,
}

/// One page of the complete receipt set for an authenticated OS session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAttachReceiptSessionPage {
    pub owner_session_binding: String,
    pub session_revision: u64,
    pub row_count: u64,
    pub records: Vec<ExternalAttachReceiptReadback>,
    pub next_cursor: Option<ExternalAttachReceiptCursor>,
}

impl ExternalAttachReceiptSessionPage {
    /// Validates one owner page against the exact request that produced it.
    /// A `None` continuation is accepted only when this page closes the pinned
    /// row-count denominator; movement is still checked by the caller's final
    /// empty page read with the same revision.
    pub fn validate_for(&self, request: &ExternalAttachReceiptSessionRead) -> Result<(), OrsError> {
        request.validate()?;
        if self.owner_session_binding != request.owner_session_binding
            || self.records.len() > usize::from(request.limit)
            || request
                .cursor
                .as_ref()
                .is_some_and(|cursor| cursor.session_revision != self.session_revision)
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "external_attach_receipt_session_page",
                reason: "page binding, limit, or pinned revision differs from its request"
                    .to_owned(),
            });
        }
        let prior_count = request
            .cursor
            .as_ref()
            .map_or(0, |cursor| cursor.emitted_rows);
        let mut prior_key = request
            .cursor
            .as_ref()
            .and_then(|cursor| cursor.after_key.as_ref());
        for record in &self.records {
            record.validate()?;
            if record.owner_session_binding != self.owner_session_binding
                || prior_key.is_some_and(|key| key.as_str() >= record.key.as_str())
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: "external_attach_receipt_session_page",
                    reason: "page rows are not strictly ordered within the requested session"
                        .to_owned(),
                });
            }
            prior_key = Some(&record.key);
        }
        let emitted_after_page = prior_count
            .checked_add(self.records.len() as u64)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        if emitted_after_page > self.row_count {
            return Err(OrsError::IntegrityProblem {
                record_type: "external_attach_receipt_session_page",
                reason: "page emits more rows than the pinned session denominator".to_owned(),
            });
        }
        match (&self.next_cursor, self.records.last()) {
            (Some(cursor), Some(last))
                if cursor.session_revision == self.session_revision
                    && cursor.after_key.as_ref() == Some(&last.key)
                    && cursor.emitted_rows == emitted_after_page
                    && emitted_after_page < self.row_count => {}
            (Some(_), _) => {
                return Err(OrsError::IntegrityProblem {
                    record_type: "external_attach_receipt_session_page",
                    reason: "continuation does not identify the owner-emitted page prefix"
                        .to_owned(),
                });
            }
            (None, _) if emitted_after_page == self.row_count => {}
            (None, _) => {
                return Err(OrsError::IntegrityProblem {
                    record_type: "external_attach_receipt_session_page",
                    reason: "terminal page does not close the pinned session denominator"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalAttachReceiptState {
    schema_version: u16,
    key: OperationIdentity,
    owner_session_binding: String,
    state_fence: StateFence,
    canonical_payload: String,
    payload_sha256: String,
    operation_order: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalAttachReceiptRow {
    state: ExternalAttachReceiptState,
    store_receipt: OperationalMutationReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalAttachSessionIndex {
    schema_version: u16,
    owner_session_binding: String,
    revision: u64,
    row_count: u64,
}

impl ExternalAttachReceiptWrite {
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_key(&self.key)?;
        validate_session_binding(&self.owner_session_binding)?;
        self.state_fence.validate().map_err(contract)?;
        validate_payload(
            &self.key,
            &self.owner_session_binding,
            &self.canonical_payload,
            &self.payload_sha256,
        )
    }
}

impl ExternalAttachReceiptRead {
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_key(&self.key)?;
        validate_session_binding(&self.owner_session_binding)?;
        self.state_fence.validate().map_err(contract)
    }
}

impl ExternalAttachReceiptSessionRead {
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_session_binding(&self.owner_session_binding)?;
        self.expected_state_fence.validate().map_err(contract)?;
        if self.limit == 0 || self.limit > crate::MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        if let Some(cursor) = &self.cursor {
            if let Some(key) = &cursor.after_key {
                validate_key(key)?;
                if cursor.emitted_rows == 0 {
                    return Err(invalid_cursor("cursor key has zero emitted rows"));
                }
            } else if cursor.emitted_rows != 0 {
                return Err(invalid_cursor("empty cursor has a nonzero emitted count"));
            }
        }
        Ok(())
    }
}

impl ExternalAttachReceiptReadback {
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_key(&self.key)?;
        validate_session_binding(&self.owner_session_binding)?;
        self.state_fence.validate().map_err(contract)?;
        validate_payload(
            &self.key,
            &self.owner_session_binding,
            &self.canonical_payload,
            &self.payload_sha256,
        )?;
        validate_store_receipt(
            &self.store_receipt,
            &self.key,
            self.store_receipt.operation_order(),
        )
        .and_then(|()| {
            let state = ExternalAttachReceiptState {
                schema_version: RECORD_SCHEMA_VERSION,
                key: self.key.clone(),
                owner_session_binding: self.owner_session_binding.clone(),
                state_fence: self.state_fence.clone(),
                canonical_payload: self.canonical_payload.clone(),
                payload_sha256: self.payload_sha256.clone(),
                operation_order: self.store_receipt.operation_order(),
            };
            let bytes = canonical_json_bytes(&state).map_err(contract)?;
            if self.store_receipt.state_sha256() != sha256_hex(&bytes) {
                return Err(OrsError::IntegrityProblem {
                    record_type: "external_attach_receipt_v1",
                    reason: "original store-issued receipt state hash differs from the readback"
                        .to_owned(),
                });
            }
            Ok(())
        })
    }
}

impl super::RedbRecoveryStore {
    /// Publishes an immutable exact receipt and atomically advances the
    /// authenticated session's revision/count index. Exact replay returns the
    /// original store receipt; any same-key difference conflicts.
    pub fn commit_external_attach_receipt(
        &self,
        request: ExternalAttachReceiptWrite,
    ) -> Result<ExternalAttachReceiptReadback, OrsError> {
        request.validate()?;
        let physical_key = physical_key(&request.owner_session_binding, &request.key);
        let index_key = index_key(&request.owner_session_binding);
        let write = self.database.begin_write().map_err(super::storage)?;
        let mut rows = write
            .open_table(super::EXTERNAL_ATTACH_RECEIPTS)
            .map_err(super::storage)?;
        if let Some(value) = rows.get(physical_key.as_str()).map_err(super::storage)? {
            let existing = decode_row(value.value())?;
            validate_row(&existing, &physical_key)?;
            let readback = readback(&existing);
            if readback.key != request.key
                || readback.owner_session_binding != request.owner_session_binding
                || readback.state_fence != request.state_fence
                || readback.canonical_payload != request.canonical_payload
                || readback.payload_sha256 != request.payload_sha256
            {
                return Err(OrsError::DuplicateConflict);
            }
            readback.validate()?;
            drop(rows);
            drop(write);
            return Ok(readback);
        }
        drop(rows);

        let prior_index = {
            let meta = write.open_table(super::META).map_err(super::storage)?;
            read_session_index(&meta, &index_key, &request.owner_session_binding)?
        };
        let order = super::RedbRecoveryStore::next_operational_order(&write)?;
        let next_count = prior_index
            .row_count
            .checked_add(1)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        let state = ExternalAttachReceiptState {
            schema_version: RECORD_SCHEMA_VERSION,
            key: request.key.clone(),
            owner_session_binding: request.owner_session_binding.clone(),
            state_fence: request.state_fence.clone(),
            canonical_payload: request.canonical_payload,
            payload_sha256: request.payload_sha256,
            operation_order: order,
        };
        let state_bytes = canonical_json_bytes(&state).map_err(contract)?;
        let state_sha256 = sha256_hex(&state_bytes);
        let store_receipt = OperationalMutationReceipt::issue(
            request.key.clone(),
            request.key.clone(),
            order,
            OperationalPhase::Active,
            state_sha256,
        )?;
        let row = ExternalAttachReceiptRow {
            state,
            store_receipt,
        };
        validate_row(&row, &physical_key)?;
        let serialized = serde_json::to_string(&row).map_err(contract)?;
        {
            let mut rows = write
                .open_table(super::EXTERNAL_ATTACH_RECEIPTS)
                .map_err(super::storage)?;
            rows.insert(physical_key.as_str(), serialized.as_str())
                .map_err(super::storage)?;
        }
        let index = ExternalAttachSessionIndex {
            schema_version: RECORD_SCHEMA_VERSION,
            owner_session_binding: request.owner_session_binding.clone(),
            revision: order,
            row_count: next_count,
        };
        let index_value = serde_json::to_string(&index).map_err(contract)?;
        write
            .open_table(super::META)
            .map_err(super::storage)?
            .insert(index_key.as_str(), index_value.as_str())
            .map_err(super::storage)?;
        write.commit().map_err(super::storage)?;
        let readback = readback(&row);
        readback.validate()?;
        Ok(readback)
    }

    /// Reads one immutable receipt by its exact claim key and OS session.
    pub fn read_external_attach_receipt(
        &self,
        request: ExternalAttachReceiptRead,
    ) -> Result<Option<ExternalAttachReceiptReadback>, OrsError> {
        request.validate()?;
        let physical_key = physical_key(&request.owner_session_binding, &request.key);
        let read = self.database.begin_read().map_err(super::storage)?;
        let rows = read
            .open_table(super::EXTERNAL_ATTACH_RECEIPTS)
            .map_err(super::storage)?;
        let Some(value) = rows.get(physical_key.as_str()).map_err(super::storage)? else {
            return Ok(None);
        };
        let row = decode_row(value.value())?;
        validate_row(&row, &physical_key)?;
        let result = readback(&row);
        if result.state_fence != request.state_fence {
            return Err(OrsError::DuplicateConflict);
        }
        result.validate()?;
        Ok(Some(result))
    }

    /// Reads one bounded page from a revision-pinned exact session receipt set.
    /// The index count is checked against the durable rows in the same redb
    /// transaction, and the next cursor names an owner-emitted prefix.
    pub fn read_external_attach_receipt_session_page(
        &self,
        request: ExternalAttachReceiptSessionRead,
    ) -> Result<ExternalAttachReceiptSessionPage, OrsError> {
        request.validate()?;
        let index_key = index_key(&request.owner_session_binding);
        let prefix = row_prefix(&request.owner_session_binding);
        let read = self.database.begin_read().map_err(super::storage)?;
        let meta = read.open_table(super::META).map_err(super::storage)?;
        let index = read_session_index(&meta, &index_key, &request.owner_session_binding)?;
        drop(meta);
        let expected_revision = request
            .cursor
            .as_ref()
            .map(|cursor| cursor.session_revision);
        if let Some(expected_revision) = expected_revision
            && expected_revision != index.revision
        {
            return Err(OrsError::ExternalAttachSessionMoved {
                expected_revision,
                observed_revision: index.revision,
            });
        }
        let rows = read
            .open_table(super::EXTERNAL_ATTACH_RECEIPTS)
            .map_err(super::storage)?;
        let mut actual_count = 0_u64;
        let mut maximum_operation_order = 0_u64;
        let mut emitted_count = 0_u64;
        let mut cursor_seen = request
            .cursor
            .as_ref()
            .is_none_or(|cursor| cursor.after_key.is_none());
        let cursor_key = request
            .cursor
            .as_ref()
            .and_then(|cursor| cursor.after_key.as_ref());
        let expected_emitted = request
            .cursor
            .as_ref()
            .map_or(0, |cursor| cursor.emitted_rows);
        let limit = usize::from(request.limit);
        let mut selected = Vec::with_capacity(limit.saturating_add(1));
        for entry in rows.range(prefix.as_str()..).map_err(super::storage)? {
            let (key, value) = entry.map_err(super::storage)?;
            if !key.value().starts_with(prefix.as_str()) {
                break;
            }
            actual_count = actual_count
                .checked_add(1)
                .ok_or(OrsError::ProjectionLimitExceeded)?;
            let row = decode_row(value.value())?;
            validate_row(&row, key.value())?;
            maximum_operation_order = maximum_operation_order.max(row.state.operation_order);
            if let Some(cursor_key) = cursor_key {
                if row.state.key == *cursor_key {
                    cursor_seen = true;
                    emitted_count = actual_count;
                    continue;
                }
                if !cursor_seen {
                    continue;
                }
            } else {
                cursor_seen = true;
            }
            if cursor_seen && selected.len() <= limit {
                selected.push(readback(&row));
            }
        }
        if actual_count != index.row_count || maximum_operation_order != index.revision {
            return Err(OrsError::IntegrityProblem {
                record_type: "external_attach_session_index_v1",
                reason: "session revision or row count differs from its durable receipt set"
                    .to_owned(),
            });
        }
        if !cursor_seen || (cursor_key.is_some() && emitted_count != expected_emitted) {
            return Err(invalid_cursor(
                "cursor does not match an owner-emitted row prefix",
            ));
        }
        selected.truncate(limit);
        let has_more =
            selected.len() == limit && actual_count > emitted_count + selected.len() as u64;
        let mut readbacks = Vec::with_capacity(selected.len());
        for record in selected {
            record
                .validate()
                .map_err(|error| OrsError::IntegrityProblem {
                    record_type: "external_attach_receipt_v1",
                    reason: error.to_string(),
                })?;
            readbacks.push(record);
        }
        let next_cursor = has_more.then(|| {
            let after_key = readbacks.last().map(|record| record.key.clone());
            ExternalAttachReceiptCursor {
                session_revision: index.revision,
                after_key,
                emitted_rows: emitted_count + readbacks.len() as u64,
            }
        });
        Ok(ExternalAttachReceiptSessionPage {
            owner_session_binding: request.owner_session_binding,
            session_revision: index.revision,
            row_count: index.row_count,
            records: readbacks,
            next_cursor,
        })
    }
}

fn read_session_index(
    meta: &impl ReadableTable<&'static str, &'static str>,
    key: &str,
    binding: &str,
) -> Result<ExternalAttachSessionIndex, OrsError> {
    let Some(value) = meta.get(key).map_err(super::storage)? else {
        return Ok(ExternalAttachSessionIndex {
            schema_version: RECORD_SCHEMA_VERSION,
            owner_session_binding: binding.to_owned(),
            revision: 0,
            row_count: 0,
        });
    };
    let index: ExternalAttachSessionIndex =
        serde_json::from_str(value.value()).map_err(contract)?;
    if index.schema_version != RECORD_SCHEMA_VERSION
        || index.owner_session_binding != binding
        || (index.row_count == 0) != (index.revision == 0)
    {
        return Err(OrsError::IntegrityProblem {
            record_type: "external_attach_session_index_v1",
            reason: "session index schema, binding, revision, or count is invalid".to_owned(),
        });
    }
    Ok(index)
}

fn decode_row(value: &str) -> Result<ExternalAttachReceiptRow, OrsError> {
    serde_json::from_str(value).map_err(|error| OrsError::IntegrityProblem {
        record_type: "external_attach_receipt_v1",
        reason: error.to_string(),
    })
}

fn readback(row: &ExternalAttachReceiptRow) -> ExternalAttachReceiptReadback {
    ExternalAttachReceiptReadback {
        key: row.state.key.clone(),
        owner_session_binding: row.state.owner_session_binding.clone(),
        state_fence: row.state.state_fence.clone(),
        canonical_payload: row.state.canonical_payload.clone(),
        payload_sha256: row.state.payload_sha256.clone(),
        store_receipt: row.store_receipt.clone(),
    }
}

fn validate_row(row: &ExternalAttachReceiptRow, stored_key: &str) -> Result<(), OrsError> {
    let state = &row.state;
    validate_key(&state.key)?;
    validate_session_binding(&state.owner_session_binding)?;
    state.state_fence.validate().map_err(contract)?;
    validate_payload(
        &state.key,
        &state.owner_session_binding,
        &state.canonical_payload,
        &state.payload_sha256,
    )?;
    if state.schema_version != RECORD_SCHEMA_VERSION
        || stored_key != physical_key(&state.owner_session_binding, &state.key)
        || state.operation_order == 0
    {
        return Err(OrsError::IntegrityProblem {
            record_type: "external_attach_receipt_v1",
            reason: "row schema, composite key, or operation order is invalid".to_owned(),
        });
    }
    let state_bytes = canonical_json_bytes(state).map_err(contract)?;
    validate_store_receipt(&row.store_receipt, &state.key, state.operation_order)?;
    if row.store_receipt.state_sha256() != sha256_hex(&state_bytes) {
        return Err(OrsError::IntegrityProblem {
            record_type: "external_attach_receipt_v1",
            reason: "original store-issued receipt state hash differs from the persisted row"
                .to_owned(),
        });
    }
    Ok(())
}

fn validate_store_receipt(
    receipt: &OperationalMutationReceipt,
    key: &OperationIdentity,
    order: u64,
) -> Result<(), OrsError> {
    if receipt.record_id() != key
        || receipt.subject_id() != key
        || receipt.operation_order() != order
        || receipt.phase() != OperationalPhase::Active
    {
        return Err(OrsError::IntegrityProblem {
            record_type: "external_attach_receipt_v1",
            reason: "store-issued receipt identity, phase, or order differs from its row"
                .to_owned(),
        });
    }
    Ok(())
}

fn validate_payload(
    key: &OperationIdentity,
    binding: &str,
    payload: &str,
    digest: &str,
) -> Result<(), OrsError> {
    if payload.is_empty()
        || digest.len() != MAX_DIGEST_LENGTH
        || digest
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        || sha256_hex(payload.as_bytes()) != digest
    {
        return Err(OrsError::InvalidField {
            field: "external_attach_receipt.payload",
            reason: "payload is empty or its exact SHA-256 digest does not match",
        });
    }
    validate_session_binding(binding)?;
    validate_key(key)
}

fn validate_key(key: &OperationIdentity) -> Result<(), OrsError> {
    let Some(digest) = key.as_str().strip_prefix("external_attach:") else {
        return Err(OrsError::InvalidField {
            field: "external_attach_receipt.key",
            reason: "must be the canonical ExternalAttach claim key",
        });
    };
    if digest.len() != MAX_DIGEST_LENGTH
        || digest
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(OrsError::InvalidField {
            field: "external_attach_receipt.key",
            reason: "must carry a lowercase SHA-256 claim digest",
        });
    }
    Ok(())
}

fn validate_session_binding(binding: &str) -> Result<(), OrsError> {
    if binding.trim().is_empty() || binding.chars().any(char::is_control) {
        return Err(OrsError::InvalidField {
            field: "external_attach_receipt.owner_session_binding",
            reason: "must be a nonempty authenticated Kernel session binding",
        });
    }
    Ok(())
}

fn physical_key(binding: &str, key: &OperationIdentity) -> String {
    format!("{}{}", row_prefix(binding), key.as_str())
}

fn row_prefix(binding: &str) -> String {
    format!("{}:", sha256_hex(binding.as_bytes()))
}

fn index_key(binding: &str) -> String {
    format!("{SESSION_INDEX_PREFIX}{}", sha256_hex(binding.as_bytes()))
}

fn invalid_cursor(reason: &'static str) -> OrsError {
    OrsError::InvalidField {
        field: "external_attach_receipt.cursor",
        reason,
    }
}

fn contract(error: impl std::fmt::Display) -> OrsError {
    OrsError::Contract(error.to_string())
}
