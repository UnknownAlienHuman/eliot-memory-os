//! Bounded logical ORS snapshot contracts — mechanical extraction from
//! `crates/kernel/eliot-ors/src/model.rs:2095-2156` (parent
//! `07a391dad6fc71d193271fafaed3e0dbffa845fc`).
//! Architecture: P-06 durable, non-semantic Operational Recovery State (ORS)
//! — bounded logical export boundary (cf. `lib.rs:1-6` "P-06 durable,
//! non-semantic Operational Recovery State").
//! This module is a **bounded logical snapshot contract, not canonical
//! authority**: it only describes a paginated logical export request
//! (`OrsSnapshotRequest`) and its store-issued evidence receipt
//! (`OrsSnapshotReceipt`) with retained `snapshot_sha256`/`entry_refs`/
//! `next_after_order` bindings. It never copies a live `redb` file, never
//! mutates durable state, never confers supervision/cutover/reservation
//! authority, and never advances any canonical ordering head. The receipt is
//! report-only; validation is limited to digest shape via
//! `model::validate_digest`. Storage/readback remains owned by `store.rs`.
//! Source parity: `OrsSnapshotRequest` and `OrsSnapshotReceipt` moved verbatim
//! (fields, derives, `serde` shape, visibility, `pub`/`pub(crate)` API
//! unchanged) — `OrsSnapshotRequest` retains `#[derive(Clone, Debug, Eq,
//! PartialEq)]` with no `Serialize` (not a wire receipt); `OrsSnapshotReceipt`
//! retains `#[derive(Clone, Debug, Eq, PartialEq, Serialize)]` with private
//! fields and `Serialize` only (no `Deserialize`). Public API re-exported via
//! `lib.rs` (`pub use snapshot_model::{OrsSnapshotRequest,
//! OrsSnapshotReceipt}`) preserving `crate::OrsSnapshot*` paths.

use serde::Serialize;

use crate::model::validate_digest;
use crate::{MAX_RECOVERY_PAGE, OrsError};

/// Bounded logical ORS export request. It never copies a live redb file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrsSnapshotRequest {
    pub after_order: u64,
    pub limit: u16,
    pub snapshot_at_ms: i64,
}

impl OrsSnapshotRequest {
    pub fn new(after_order: u64, limit: u16, snapshot_at_ms: i64) -> Result<Self, OrsError> {
        if limit == 0 || limit > MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        Ok(Self {
            after_order,
            limit,
            snapshot_at_ms,
        })
    }
}

/// Store-issued logical snapshot receipt with retained evidence bindings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsSnapshotReceipt {
    snapshot_at_ms: i64,
    entry_refs: Vec<String>,
    snapshot_sha256: String,
    next_after_order: Option<u64>,
}

impl OrsSnapshotReceipt {
    pub const fn snapshot_at_ms(&self) -> i64 {
        self.snapshot_at_ms
    }

    pub fn entry_refs(&self) -> &[String] {
        &self.entry_refs
    }

    pub fn snapshot_sha256(&self) -> &str {
        &self.snapshot_sha256
    }

    pub const fn next_after_order(&self) -> Option<u64> {
        self.next_after_order
    }

    pub(crate) fn issue(
        snapshot_at_ms: i64,
        entry_refs: Vec<String>,
        snapshot_sha256: String,
        next_after_order: Option<u64>,
    ) -> Result<Self, OrsError> {
        validate_digest(&snapshot_sha256, "ors_snapshot_sha256")?;
        Ok(Self {
            snapshot_at_ms,
            entry_refs,
            snapshot_sha256,
            next_after_order,
        })
    }
}
