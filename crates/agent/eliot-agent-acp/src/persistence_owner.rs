//! Persistence-owner seam for durable host-event ingest (issue #1934, I7.23).
//!
//! The in-memory [`DurableHostEventJournal`](crate::DurableHostEventJournal)
//! owns the durable *relation* (transport hash, raw-or-redacted record,
//! normalized envelope, disposition) but performs no I/O and grants no
//! authority. This module names the owner trait it sits behind so the
//! canonical-store line (A/store) can bind physical durability without
//! touching the bridge producer or the reconnect driver: both depend only on
//! [`HostEventPersistenceOwner`], never on the concrete journal.
//!
//! Binding contract for A/store: implement this trait on the canonical store
//! bridge (or on a store-backed journal facade) and pass it to
//! [`produce_allowed`](crate::produce_allowed),
//! [`produce_redacted`](crate::produce_redacted), and
//! [`drive_reconnect`](crate::drive_reconnect). The trait carries no I/O,
//! no canonical-store types, and no `EventEnvelope`-disposition store; those
//! remain A/store-owned. Cursor ordering invariants (commit advances the
//! durable cursor, acknowledgement never passes it, reconnect replays after
//! the acked cursor) are part of the trait contract and must hold for every
//! implementor.

use crate::{
    DurableHostEventJournal, DurableHostEventRecord, EventKey, IngestError, ReplayItem,
    StageAllowed, StageOutcome, StageRedacted, StreamCursorState,
};

/// Persistence owner behind the host-event ingest journal.
///
/// The implementor durably relates each event's transport hash, stored
/// raw-or-redacted bytes, normalized envelope, and disposition, and publishes
/// per-stream cursors only through [`commit`](Self::commit). Staging alone
/// never advances a cursor; acknowledgement never passes the durable cursor;
/// [`pending_for_reconnect`](Self::pending_for_reconnect) replays everything
/// after the acked cursor in ascending order. Duplicate delivery of the same
/// transport bytes or stream cursor is idempotent.
pub trait HostEventPersistenceOwner {
    /// Stages admissible raw transport bytes plus their bound envelope.
    /// Fails closed on denied content; never advances a cursor.
    fn stage_allowed(&mut self, request: StageAllowed<'_>) -> Result<StageOutcome, IngestError>;

    /// Stages a redacted event: the original bytes are hashed and scanned but
    /// never stored. Never advances a cursor.
    fn stage_redacted(&mut self, request: StageRedacted<'_>) -> Result<StageOutcome, IngestError>;

    /// Commits one staged record, advancing the per-stream durable cursor to
    /// its sequence. Commits require contiguity; re-commit is idempotent.
    fn commit(&mut self, key: &EventKey) -> Result<StreamCursorState, IngestError>;

    /// Acknowledges downstream receipt up to `sequence`, which must not pass
    /// the durable cursor. Monotonic; never moves backwards.
    fn acknowledge(
        &mut self,
        stream_id: &str,
        sequence: u64,
    ) -> Result<StreamCursorState, IngestError>;

    /// Replays everything after the last acknowledged cursor for a stream, in
    /// ascending sequence order. Never synthesizes events.
    fn pending_for_reconnect(&self, stream_id: &str) -> Vec<ReplayItem>;

    /// Applies one committed envelope to state exactly once; duplicates
    /// return `false` without a second application.
    fn record_application(&mut self, key: &EventKey) -> Result<bool, IngestError>;

    /// Returns the per-stream cursor state. Unknown streams report zero
    /// cursors; cursor state is never synthesized from turn or process state.
    fn cursor(&self, stream_id: &str) -> StreamCursorState;

    /// Returns the record stored under a stream cursor, if any.
    fn get(&self, key: &EventKey) -> Option<&DurableHostEventRecord>;
}

impl HostEventPersistenceOwner for DurableHostEventJournal {
    fn stage_allowed(&mut self, request: StageAllowed<'_>) -> Result<StageOutcome, IngestError> {
        Self::stage_allowed(self, request)
    }

    fn stage_redacted(&mut self, request: StageRedacted<'_>) -> Result<StageOutcome, IngestError> {
        Self::stage_redacted(self, request)
    }

    fn commit(&mut self, key: &EventKey) -> Result<StreamCursorState, IngestError> {
        Self::commit(self, key)
    }

    fn acknowledge(
        &mut self,
        stream_id: &str,
        sequence: u64,
    ) -> Result<StreamCursorState, IngestError> {
        Self::acknowledge(self, stream_id, sequence)
    }

    fn pending_for_reconnect(&self, stream_id: &str) -> Vec<ReplayItem> {
        Self::pending_for_reconnect(self, stream_id)
    }

    fn record_application(&mut self, key: &EventKey) -> Result<bool, IngestError> {
        Self::record_application(self, key)
    }

    fn cursor(&self, stream_id: &str) -> StreamCursorState {
        Self::cursor(self, stream_id)
    }

    fn get(&self, key: &EventKey) -> Option<&DurableHostEventRecord> {
        Self::get(self, key)
    }
}
