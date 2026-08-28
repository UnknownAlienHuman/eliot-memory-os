//! ORS recovery projection and bounded recovery-inbox ingress.
//!
//! Architecture: P-06 ORS / A13.6 keeps recovery durable, bounded,
//! non-semantic, and non-authoritative (`src/lib.rs:1-6`).
//! Implementation: I5.2 keeps persistence at the ORS boundary and I2.1 keeps
//! this cohesive capability in a private child module.
//! Source parity: projection, bounded recovery scanning, inbox import, and
//! private helpers moved from `store.rs` without semantic changes. Decoding
//! remains delegated to the canonical `store::persistence_codec` module.
//!
//! Ownership: this child owns only neutral recovery projections, bounded
//! recovery scanning, and recovery-inbox import. The parent retains
//! transaction/durability coordination, reconciliation, lifecycle, and Kernel
//! authority.

use redb::{ReadableDatabase, ReadableTable};

use super::{
    DurableInboxRecord, DurableOperationalRecord, OperationalKind, OperationalPhase,
    RecoveryCursor, RecoveryInboxDisposition, RecoveryInboxItem, RecoveryInboxReceipt,
    RecoveryPage, RedbRecoveryStore, ReservationRecord, ReservationState, decode, decode_named,
    encode, storage,
};
use crate::{OpaqueLabel, OperationalControlProjection, OrsError};

use eliot_runtime_contracts::{HealthDimension, OperationalRecoveryState};

fn push_bounded(values: &mut Vec<String>, value: String, limit: usize) -> Result<(), OrsError> {
    if values.len() == limit {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    values.push(value);
    Ok(())
}

fn active_operational_refs(
    store: &RedbRecoveryStore,
    kinds: &[OperationalKind],
    limit: u16,
) -> Result<Vec<String>, OrsError> {
    let read = store.database.begin_read().map_err(storage)?;
    let table = read
        .open_table(super::OPERATIONAL_CURRENT)
        .map_err(storage)?;
    let mut refs = Vec::new();
    for row in table.iter().map_err(storage)? {
        let (_, value) = row.map_err(storage)?;
        let record: DurableOperationalRecord = decode_named(value.value(), "operational_current")?;
        if kinds.contains(&record.kind)
            && matches!(
                record.phase,
                OperationalPhase::Active | OperationalPhase::Applying
            )
        {
            push_bounded(
                &mut refs,
                record.input.subject_id.as_str().to_owned(),
                usize::from(limit),
            )?;
        }
    }
    refs.sort();
    Ok(refs)
}

impl RedbRecoveryStore {
    pub fn projection_page(
        &self,
        active_receipt: &eliot_receipts::ReceiptEnvelope,
        cursor: RecoveryCursor,
    ) -> Result<(OperationalRecoveryState, Option<u64>), OrsError> {
        let page = recover_page(self, cursor)?;
        let next_after_order = page.next_after_order;
        let mut pending_operation_refs = Vec::new();
        let mut recovery_intent_refs = Vec::new();
        for record in page.records {
            pending_operation_refs.push(record.token.operation_id.as_str().to_owned());
            if record.state == ReservationState::Reconciling {
                recovery_intent_refs.push(record.token.reservation_id.as_str().to_owned());
            }
        }
        active_receipt
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        self.evidence.verify_receipt(active_receipt)?;
        let active_epoch = active_receipt.core.authority.authority_epoch.value();
        let read = self.database.begin_read().map_err(storage)?;
        let operational = read
            .open_table(super::OPERATIONAL_CURRENT)
            .map_err(storage)?;
        let mut authority_snapshot_found = false;
        for row in operational.iter().map_err(storage)? {
            let (_, value) = row.map_err(storage)?;
            let record: DurableOperationalRecord =
                decode_named(value.value(), "operational_current")?;
            if record.kind == OperationalKind::AuthoritySnapshot
                && record.phase == OperationalPhase::Active
                && record.input.authority_epoch.current.epoch == active_epoch
            {
                authority_snapshot_found = true;
                break;
            }
        }
        if !authority_snapshot_found {
            return Err(OrsError::AuthoritySnapshotUnavailable);
        }
        let active_generation_refs = active_operational_refs(
            self,
            &[
                OperationalKind::GenerationTransition,
                OperationalKind::GenerationCutover,
            ],
            cursor.limit,
        )?;
        let inbox = read.open_table(super::RECOVERY_INBOX).map_err(storage)?;
        for row in inbox.iter().map_err(storage)? {
            let (_, value) = row.map_err(storage)?;
            let record: DurableInboxRecord = decode_named(value.value(), "recovery_inbox")?;
            if record.disposition == RecoveryInboxDisposition::Imported {
                push_bounded(
                    &mut recovery_intent_refs,
                    record.item.item_id.as_str().to_owned(),
                    usize::from(cursor.limit),
                )?;
            }
        }
        recovery_intent_refs.sort();
        recovery_intent_refs.dedup();
        let projection = OperationalRecoveryState {
            ors_revision: format!("eliot.kernel.ors/v{}", crate::CONTRACT_VERSION),
            integrity: HealthDimension::Healthy,
            authority_epoch: active_receipt.core.authority.authority_epoch,
            pending_operation_refs,
            active_generation_refs,
            recovery_intent_refs,
        };
        projection
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        Ok((projection, next_after_order))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the projection exhaustively classifies each persisted operational kind in one scan"
    )]
    pub fn control_projection_page(
        &self,
        cursor: RecoveryCursor,
    ) -> Result<(OperationalControlProjection, Option<u64>), OrsError> {
        let page = recover_page(self, cursor)?;
        let next_after_order = page.next_after_order;
        let pending_operation_refs = page
            .records
            .into_iter()
            .map(|record| record.token.operation_id.as_str().to_owned())
            .collect();
        let read = self.database.begin_read().map_err(storage)?;
        let current = read
            .open_table(super::OPERATIONAL_CURRENT)
            .map_err(storage)?;
        let mut authority: Option<(u64, crate::EpochLineage)> = None;
        let mut active_generation_refs = Vec::new();
        let mut active_session_refs = Vec::new();
        let mut active_user_broker_refs = Vec::new();
        let mut active_capability_refs = Vec::new();
        let mut job_checkpoint_refs = Vec::new();
        let mut delivery_cursor_refs = Vec::new();
        for row in current.iter().map_err(storage)? {
            let (_, value) = row.map_err(storage)?;
            let record: DurableOperationalRecord =
                decode_named(value.value(), "operational_current")?;
            let subject = record.input.subject_id.as_str().to_owned();
            match (record.kind, record.phase) {
                (OperationalKind::AuthoritySnapshot, OperationalPhase::Active) => {
                    if authority
                        .as_ref()
                        .is_none_or(|(order, _)| *order < record.operation_order)
                    {
                        authority =
                            Some((record.operation_order, record.input.authority_epoch.clone()));
                    }
                }
                (
                    OperationalKind::GenerationTransition | OperationalKind::GenerationCutover,
                    OperationalPhase::Active | OperationalPhase::Applying,
                ) => push_bounded(
                    &mut active_generation_refs,
                    subject,
                    usize::from(cursor.limit),
                )?,
                (OperationalKind::SessionBinding, OperationalPhase::Active) => {
                    push_bounded(&mut active_session_refs, subject, usize::from(cursor.limit))?;
                }
                (OperationalKind::UserBroker, OperationalPhase::Active) => {
                    push_bounded(
                        &mut active_user_broker_refs,
                        subject,
                        usize::from(cursor.limit),
                    )?;
                }
                (
                    OperationalKind::CapabilityGrant | OperationalKind::CapabilityIntroduction,
                    OperationalPhase::Active,
                ) => push_bounded(
                    &mut active_capability_refs,
                    subject,
                    usize::from(cursor.limit),
                )?,
                (OperationalKind::JobCheckpoint, OperationalPhase::Active) => {
                    push_bounded(&mut job_checkpoint_refs, subject, usize::from(cursor.limit))?;
                }
                (OperationalKind::DeliveryCursor, OperationalPhase::Active) => {
                    push_bounded(
                        &mut delivery_cursor_refs,
                        subject,
                        usize::from(cursor.limit),
                    )?;
                }
                _ => {}
            }
        }
        let authority_lineage = authority
            .map(|(_, lineage)| lineage)
            .ok_or(OrsError::AuthoritySnapshotUnavailable)?;
        let inbox = read.open_table(super::RECOVERY_INBOX).map_err(storage)?;
        let mut recovery_inbox_refs = Vec::new();
        for row in inbox.iter().map_err(storage)? {
            let (_, value) = row.map_err(storage)?;
            let record: DurableInboxRecord = decode_named(value.value(), "recovery_inbox")?;
            if record.disposition == RecoveryInboxDisposition::Imported {
                push_bounded(
                    &mut recovery_inbox_refs,
                    record.item.item_id.as_str().to_owned(),
                    usize::from(cursor.limit),
                )?;
            }
        }
        for refs in [
            &mut active_generation_refs,
            &mut active_session_refs,
            &mut active_user_broker_refs,
            &mut active_capability_refs,
            &mut job_checkpoint_refs,
            &mut delivery_cursor_refs,
            &mut recovery_inbox_refs,
        ] {
            refs.sort();
            refs.dedup();
        }
        Ok((
            OperationalControlProjection {
                authority_lineage,
                pending_operation_refs,
                active_generation_refs,
                active_session_refs,
                active_user_broker_refs,
                active_capability_refs,
                job_checkpoint_refs,
                delivery_cursor_refs,
                recovery_inbox_refs,
            },
            next_after_order,
        ))
    }
}

pub(super) fn recover_page(
    store: &RedbRecoveryStore,
    cursor: RecoveryCursor,
) -> Result<RecoveryPage, OrsError> {
    if cursor.limit == 0 || cursor.limit > crate::MAX_RECOVERY_PAGE {
        return Err(OrsError::InvalidCursorLimit);
    }
    let read = store.database.begin_read().map_err(storage)?;
    let orders = read
        .open_table(super::RESERVATION_ORDERS)
        .map_err(storage)?;
    let reservations = read.open_table(super::RESERVATIONS).map_err(storage)?;
    let mut records = Vec::with_capacity(usize::from(cursor.limit) + 1);
    for row in orders.iter().map_err(storage)? {
        let (order, reservation_id) = row.map_err(storage)?;
        let parsed_order =
            order
                .value()
                .parse::<u64>()
                .map_err(|error| OrsError::IntegrityProblem {
                    record_type: "reservation_order",
                    reason: error.to_string(),
                })?;
        if parsed_order <= cursor.after_order {
            continue;
        }
        let reservation_id = OpaqueLabel::new(reservation_id.value()).map_err(|error| {
            OrsError::IntegrityProblem {
                record_type: "reservation_order",
                reason: error.to_string(),
            }
        })?;
        let value = reservations
            .get(reservation_id.as_str())
            .map_err(storage)?
            .ok_or_else(|| OrsError::IntegrityProblem {
                record_type: "reservation_order",
                reason: "dangling reservation order index".to_owned(),
            })?;
        let record: ReservationRecord = decode(value.value())?;
        if record.token.reservation_order != parsed_order {
            return Err(OrsError::IntegrityProblem {
                record_type: "reservation_order",
                reason: "order index disagrees with reservation".to_owned(),
            });
        }
        if !record.state.is_terminal() {
            records.push(record);
            if records.len() > usize::from(cursor.limit) {
                break;
            }
        }
    }
    let has_more = records.len() > usize::from(cursor.limit);
    if has_more {
        records.pop();
    }
    let next_after_order = has_more
        .then(|| records.last().map(|record| record.token.reservation_order))
        .flatten();
    Ok(RecoveryPage {
        records,
        next_after_order,
    })
}

pub(super) fn import_recovery_inbox(
    store: &RedbRecoveryStore,
    item: RecoveryInboxItem,
) -> Result<RecoveryInboxReceipt, OrsError> {
    item.validate()?;
    store.evidence.verify_recovery_inbox(&item)?;
    let write = store.database.begin_write().map_err(storage)?;
    {
        let inbox = write.open_table(super::RECOVERY_INBOX).map_err(storage)?;
        if let Some(value) = inbox.get(item.item_id.as_str()).map_err(storage)? {
            let record: DurableInboxRecord = decode_named(value.value(), "recovery_inbox")?;
            if record.item == item {
                let receipt = crate::OperationalMutationReceipt::issue(
                    record.item.item_id.clone(),
                    record.item.envelope.operation_or_checkpoint_id.clone(),
                    record.operation_order,
                    crate::OperationalPhase::Staged,
                    crate::model::sha256_hex(encode(&record)?.as_bytes()),
                )?;
                return Ok(RecoveryInboxReceipt::from_receipt(receipt));
            }
            return Err(OrsError::DuplicateConflict);
        }
    }
    let record = DurableInboxRecord {
        item,
        disposition: RecoveryInboxDisposition::Imported,
        operation_order: RedbRecoveryStore::next_operational_order(&write)?,
        terminal_receipt_id: None,
        terminal_receipt_sha256: None,
    };
    let encoded = encode(&record)?;
    let receipt = crate::OperationalMutationReceipt::issue(
        record.item.item_id.clone(),
        record.item.envelope.operation_or_checkpoint_id.clone(),
        record.operation_order,
        crate::OperationalPhase::Staged,
        crate::model::sha256_hex(encoded.as_bytes()),
    )?;
    let mut inbox = write.open_table(super::RECOVERY_INBOX).map_err(storage)?;
    inbox
        .insert(record.item.item_id.as_str(), encoded.as_str())
        .map_err(storage)?;
    drop(inbox);
    let history_key = format!(
        "{:020}:{}",
        record.operation_order,
        record.item.item_id.as_str()
    );
    let mut history = write
        .open_table(super::RECOVERY_INBOX_HISTORY)
        .map_err(storage)?;
    history
        .insert(history_key.as_str(), encoded.as_str())
        .map_err(storage)?;
    drop(history);
    write.commit().map_err(storage)?;
    Ok(RecoveryInboxReceipt::from_receipt(receipt))
}
