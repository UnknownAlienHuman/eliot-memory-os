//! Control WAL wire/data model cell — mechanical extraction from `crates/eliot-store/src/control_wal.rs`.
//! Architecture A13.2 (Kernel and failure domains): durable control WAL boundary, single owned write path, health and recovery entrypoint; this cell does not own Kernel authority.
//! Implementation I5.1/I5.22 (store/surreal bridge) and I16.1 (four surfaces truth-boundary): WAL wire types are durable projections, not live authority; exact `serde` JSON shape preserved.
//! Source anchors: `crates/eliot-store/src/control_wal.rs:671-709` (`WalPendingWrite`, `WalFailedWrite`, `WalDeadLetter`, `WalProjectHead`, `WalWriteState`) and `crates/eliot-store/src/control_wal.rs:711-723` private `encode`/`decode` seams retained in `control_wal.rs`.
//! Responsibility: wire/data model types only — `WalPendingWrite`, `WalFailedWrite`, `WalDeadLetter`, `WalProjectHead`, `WalWriteState` with exact `Clone`, `Debug`, `Serialize`, `Deserialize` derives and field order.
//! Explicit non-ownership: no canonical authority, no write ownership, no `ControlWal` facade, no `redb` `Database`/table definitions, no `META`/`PENDING_WRITES`/`COMMITTED_RECEIPTS`/`FAILED_WRITES`/`DEAD_LETTERS`/`PROJECT_HEADS` tables, no operation runtime/restart window/supervision cursor/seal staging logic, no provider/handshake/migration/atomic-write, no Dreamer/Luna/frozen scope. Mechanical split only — no semantic redesign; public API, imports, `serde` shape, and `ControlWal` facade unchanged.

use eliot_types::{
    MemoryRevision, MemoryWriteEnvelope, ProjectId, ProjectSequence, WriteId, WriteReceipt,
    WriteStatus,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalPendingWrite {
    pub envelope: MemoryWriteEnvelope,
    pub status: WriteStatus,
    pub attempts: u32,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalFailedWrite {
    pub write_id: WriteId,
    pub status: WriteStatus,
    pub pending: Option<WalPendingWrite>,
    pub receipt: Option<WriteReceipt>,
    pub error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalDeadLetter {
    pub write_id: WriteId,
    pub pending: Option<WalPendingWrite>,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalProjectHead {
    pub project_id: ProjectId,
    pub memory_revision: MemoryRevision,
    pub project_sequence: ProjectSequence,
    pub last_write_id: WriteId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WalWriteState {
    Pending(Box<WalPendingWrite>),
    Committed(Box<WriteReceipt>),
    Failed(Box<WalFailedWrite>),
    DeadLetter(Box<WalDeadLetter>),
}
