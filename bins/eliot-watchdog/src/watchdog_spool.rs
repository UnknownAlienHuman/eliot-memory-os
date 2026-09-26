//! Physical protected spool cell for the independent Runtime 0.17 watchdog.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01, ARCH-WDG-02.
//! Implementation: I8.1, I8.3, I8.10, I8.13, I2.23.
//! Physical protected spool only — no semantic/canonical/Kernel/Governor
//! authority and no new default or retry; bytes/layout/recovery/high-water/fail-closed
//! behavior is preserved verbatim from the reviewed production cell.

use std::path::{Path, PathBuf};

use eliot_contracts::sha256_hex;
use eliot_platform_windows::ProtectedRuntimePathLease;
use eliot_watchdog_core::{
    WatchdogSpoolAcknowledgement, WatchdogSpoolCursor, WatchdogSpoolExportBatch,
    WatchdogSpoolExportEntry, WatchdogSpoolPayloadKind, WatchdogSpoolReconciliationError,
    acknowledgement_advances_cursor, is_duplicate_ack, validate_acknowledgement, validate_batch,
    validate_batch_freshness, validate_cursor,
};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};

use crate::{SERVICE_NAME, SpoolError, WatchdogRuntimeBinding, current_unix_ms};

pub(crate) mod backup;
mod codec;
pub mod export_driver;
/// Spool-local intent records (I8.1 `problem_intent` / `incident_intent`) and
/// the Watchdog-owned deterministic escalation rule that mints them.
/// The shared owner-neutral export classes stay unextended: intents persist as
/// codec variants, travel inside their export window under the existing
/// `Recovery` class, are reconciled through the fenced Kernel
/// `watchdog-spool-batch-v1` intent route, and are never removed by compaction
/// so the original Watchdog record stays linked to the Governor's decision.
pub(crate) mod intent;

pub use backup::{
    CaptureFenceParams, SpoolCoverageDenominator, SpoolFenceEntryKind,
    SpoolImportReplayDisposition, SpoolImportReplayLedger, SpoolMarkerDetail, SpoolObservedDigest,
    SpoolRestoreDisposition, SpoolRestoreStep, WatchdogSpoolBackupLimits, WatchdogSpoolFence,
    WatchdogSpoolSnapshotPage, acceptance_allowed, capture_fence, check_page_continuation,
    read_page, reconcile_restore, validate_isolated_destination, validate_restore_chain,
    verify_page_digest,
};
pub use codec::{WatchdogSpoolEntry, WatchdogSpoolHeader, WatchdogSpoolPayload};
use codec::{
    collect_entries, decode_header, decode_high_water, encode_header, read_high_water,
    validate_high_water,
};
pub(crate) use codec::{encode_entry, encode_high_water, validate_header};

pub(crate) const SPOOL_SCHEMA_VERSION: u16 = 1;
pub(crate) const SPOOL_HEADER_KEY: u64 = 0;
pub(crate) const SPOOL_MAX_RECORDS: u64 = 4096;
pub(crate) const SPOOL_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const SPOOL_MAX_RECORD_BYTES: usize = 64 * 1024;
pub(crate) const WATCHDOG_SPOOL_FILE_NAME: &str = "watchdog.redb";
pub(crate) const SPOOL_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eliot_watchdog_spool_v1");
pub(crate) const SPOOL_HIGH_WATER_KEY: u64 = 0;
pub(crate) const SPOOL_HIGH_WATER_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eliot_watchdog_spool_high_water_v1");
/// Default and hard ceiling for the number of spool records covered by one
/// export batch.
///
/// A single export stays small against `SPOOL_MAX_RECORDS`: 256 records are
/// one sixteenth of the 4096-record retention ceiling, so a full spool drains
/// in a bounded handful of exports while no single export can pin the sink
/// with an unbounded window.
pub(crate) const EXPORT_MAX_ITEMS: usize = 256;
/// Default and hard ceiling for the total raw entry bytes covered by one
/// export batch.
///
/// 512 KiB is one eighth of `SPOOL_MAX_BYTES` (4 MiB) and eight times
/// `SPOOL_MAX_RECORD_BYTES` (64 KiB), so any single retained record always
/// fits while a full spool still drains in a bounded handful of exports.
pub(crate) const EXPORT_MAX_BYTES: u64 = 512 * 1024;
/// Acknowledgement window for one export batch, in milliseconds.
///
/// The spool owner stamps `created_at_ms` from its own clock and enforces the
/// window with its own clock at acknowledgement time. An expired batch fails
/// closed and the sink retries with a fresh export over the same immutable
/// records; the window never enters the batch digest material.
pub(crate) const EXPORT_BATCH_TTL_MS: u64 = 60_000;
/// Storage revision of the persisted export cursor record.
///
/// This intentionally equals `SPOOL_SCHEMA_VERSION` today. A future revision
/// bump refuses to mix cursor generations instead of reinterpreting them.
pub(crate) const SPOOL_EXPORT_CURSOR_SCHEMA_VERSION: u16 = 1;
/// Single-key cursor row inside the export cursor table.
pub(crate) const SPOOL_EXPORT_CURSOR_KEY: u64 = 0;
/// Cursor table inside the same `watchdog.redb` file.
///
/// The spool keeps its single writer and never shards cursor state into a
/// second file; every cursor read and write below runs inside the same
/// transactional patterns as the header and high-water paths.
pub(crate) const SPOOL_EXPORT_CURSOR_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eliot_watchdog_spool_export_cursor_v1");
/// Single-key row of the Watchdog-owned deterministic escalation-rule state.
///
/// The rule state lives in the same `watchdog.redb` file as the records it
/// mints, so a restart cannot reset the threshold and silently skip
/// escalation: only a live Governor admission closes an open episode, and the
/// episode survives a Problem emission and a Watchdog restart alike.
pub(crate) const SPOOL_INTENT_RULE_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eliot_watchdog_spool_intent_rule_v1");
/// Single-key cursor-style key of the rule-state row.
pub(crate) const SPOOL_INTENT_RULE_KEY: u64 = 0;
/// Per-record table of durable submit-once reconciliation receipts.
///
/// This is the exactly-once ledger for fenced-Kernel intent reconciliation: it
/// is keyed by the retained Watchdog spool sequence, so one spool record can
/// never acquire two receipts and a retry after a lost acknowledgement observes
/// the existing receipt instead of submitting again.
///
/// Scope, stated exactly: this ledger is per spool **record**. It says nothing
/// about how many intents an episode mints — an episode reaches each configured
/// threshold once, which is the rule's own decision, not this ledger's — and a
/// receipt never claims the Governor performed a canonical transition.
pub(crate) const SPOOL_INTENT_RECEIPT_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eliot_watchdog_spool_intent_receipt_v1");
/// Storage revision of one durable submit-once receipt.
///
/// Distinct from the rule-state revision so a future receipt-shape change
/// refuses to reinterpret an existing ledger instead of mixing generations.
pub(crate) const INTENT_RECEIPT_SCHEMA_VERSION: u16 = 1;
/// Maximum accepted length for one persisted cursor identity string.
///
/// Cursor identities are short installer-bound names such as
/// `installation-7`. The cap keeps the single-key cursor row tiny and fails
/// closed on corrupt oversized values instead of growing it without bound.
pub(crate) const SPOOL_EXPORT_CURSOR_IDENTITY_MAX: usize = 1024;
/// Stable reason marker for quarantined isolated-restore evidence.
///
/// Each imported restore step is appended through the existing append path as
/// a `Recovery` record whose reason is this marker followed by the exact
/// source installation, stable operation identity, and step index, with the
/// step digest as the corrupt digest. The fixed framing lets a repeated import
/// recognise its own quarantined rows (duplicate, append nothing) and reject
/// changed content under the same operation identity, without touching lease,
/// heartbeat, authority, or epoch state.
const BACKUP_IMPORT_REASON_MARKER: &str = "isolated-restore historical evidence";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpoolAppendOutcome {
    /// Record stored without retention pressure.
    Stored,
    /// Retention pressure evicted older records to admit the new one.
    Pressure { evicted_records: u64 },
}

/// Bounded window for one spool export.
///
/// Both caps apply together: export stops at whichever bound is reached
/// first, after always covering at least one record so a non-empty spool
/// always makes progress. The defaults equal `EXPORT_MAX_ITEMS` and
/// `EXPORT_MAX_BYTES`, which are also hard ceilings; a caller window outside
/// those ceilings is rejected instead of silently clamped so an exact retry
/// of the same window stays byte-equivalent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogSpoolExportLimits {
    pub max_items: usize,
    pub max_bytes: u64,
}

impl Default for WatchdogSpoolExportLimits {
    fn default() -> Self {
        Self {
            max_items: EXPORT_MAX_ITEMS,
            max_bytes: EXPORT_MAX_BYTES,
        }
    }
}

impl WatchdogSpoolExportLimits {
    /// Rejects unbounded or unprogressable windows before any spool read.
    ///
    /// The lower byte bound is one maximum-size record, which guarantees the
    /// first covered record always fits and export always makes progress.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] carrying the exact reconciliation
    /// field failure when either bound is zero or above its hard ceiling.
    fn validate(&self) -> Result<(), SpoolError> {
        if self.max_items == 0 || self.max_items > EXPORT_MAX_ITEMS {
            return Err(WatchdogSpoolReconciliationError::InvalidField("max_items").into());
        }
        if self.max_bytes < SPOOL_MAX_RECORD_BYTES as u64 || self.max_bytes > EXPORT_MAX_BYTES {
            return Err(WatchdogSpoolReconciliationError::InvalidField("max_bytes").into());
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct WatchdogSpool {
    pub(crate) database: Database,
    pub(crate) _path_lease: Option<ProtectedRuntimePathLease>,
}

impl WatchdogSpool {
    pub(crate) fn open_runtime_binding(
        binding: &WatchdogRuntimeBinding,
    ) -> Result<Self, SpoolError> {
        let _span = tracing::debug_span!("watchdog.spool_open").entered();
        tracing::debug!(
            event = "watchdog.spool_open_attempted",
            observation = "attempted",
            "opening runtime spool binding without payload material"
        );
        let path = watchdog_spool_path(binding.watchdog_state_root());
        let path_lease = ProtectedRuntimePathLease::open_or_create_absolute(&path)
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        if path_lease.path() != path {
            return Err(SpoolError::InvalidProtectedRoot);
        }
        path_lease
            .verify_path_identity()
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        let database = Database::open(path_lease.path())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let spool = Self {
            database,
            _path_lease: Some(path_lease),
        };
        spool.initialize_or_recover()?;
        Ok(spool)
    }

    pub(crate) fn open_existing_runtime_binding(
        binding: &WatchdogRuntimeBinding,
    ) -> Result<Self, SpoolError> {
        let path = watchdog_spool_path(binding.watchdog_state_root());
        let path_lease = ProtectedRuntimePathLease::open_existing_absolute(&path)
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        if path_lease.path() != path {
            return Err(SpoolError::InvalidProtectedRoot);
        }
        path_lease
            .verify_path_identity()
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        let database = Database::open(path_lease.path())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        Ok(Self {
            database,
            _path_lease: Some(path_lease),
        })
    }

    pub(crate) fn readback(&self) -> Result<Vec<WatchdogSpoolEntry>, SpoolError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let table = match read.open_table(SPOOL_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        };
        let header = table
            .get(SPOOL_HEADER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .ok_or_else(|| SpoolError::Corrupt("spool header is missing".to_owned()))?;
        let header = decode_header(header.value())?;
        let entries = collect_entries(&table)?;
        validate_header(&header, &entries)?;
        let high_water = read.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!("high-water metadata is unavailable: {error}"))
        })?;
        let high_water = read_high_water(&high_water)?
            .ok_or_else(|| SpoolError::Corrupt("high-water metadata is missing".to_owned()))?;
        validate_high_water(&header, &entries, high_water)?;
        Ok(entries)
    }

    /// Captures an immutable bounded backup fence over the retained spool.
    ///
    /// Validates `limits` before any spool read so no unbounded buffer is
    /// ever collected, then opens one bounded coherent read transaction over
    /// the header, high-water, and entries (mirroring [`readback`](Self::readback)),
    /// decodes and validates through the existing codec validators, and
    /// delegates fence construction to [`backup::capture_fence`]. The result
    /// is an immutable data handle carrying digests and redacted receipts
    /// only: no live redb file is opened or copied, and no lease, heartbeat,
    /// supervision authority, epoch, restart, deletion, or cutover state is
    /// touched.
    ///
    /// Two owner-level refusals run before the capture, because this owner
    /// holds nothing that could satisfy them honestly:
    ///
    /// - A capture naming a `canonical_ref` or `ors_ref` is refused. Coherence
    ///   with another owner's capture is established by the cross-owner
    ///   coordinator's exact fence protocol, which this owner does not
    ///   participate in; it can neither verify a caller-asserted reference nor
    ///   carry one as evidence. The honest outcome is refusal, not a recorded
    ///   reference.
    /// - A capture whose bounded work would exceed `limits.max_work_units` is
    ///   refused, so the admitted work ceiling is consulted against the real
    ///   retained member count instead of only being shape-validated. For the
    ///   admitted default window that ceiling equals the retention ceiling this
    ///   owner already enforces, so it is a safety net against an over-limit or
    ///   corrupt spool rather than a bound that binds an ordinary capture.
    ///
    /// The owner-held installation identity, generation, and admitted
    /// requester are bound by the composition's owner-bound
    /// [`WatchdogBackupPort`](crate::WatchdogBackupPort); the spool itself
    /// holds no installation identity, so it never compares a caller value
    /// against itself.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the limits window is unbounded or
    /// over-ceiling, the capture names a cross-owner reference, the retained
    /// work exceeds the bounded work ceiling, the spool header or high-water
    /// is missing or invalid, or any retained entry is expired, missing,
    /// duplicated, conflicting, or malformed.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "955 owner-method contract takes the capture bindings by value; the fence builder borrows them"
    )]
    pub fn snapshot_backup(
        &self,
        params: backup::CaptureFenceParams,
        limits: WatchdogSpoolBackupLimits,
    ) -> Result<WatchdogSpoolFence, SpoolError> {
        limits.validate()?;
        if params.canonical_ref.is_some() || params.ors_ref.is_some() {
            return Err(SpoolError::Corrupt(
                "watchdog spool backup capture refuses an unverifiable canonical/ORS reference; coherence belongs to the cross-owner fence protocol"
                    .to_owned(),
            ));
        }
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let table = match read.open_table(SPOOL_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Err(SpoolError::Corrupt(
                    "watchdog spool backup capture covers no retained entries; a bare record vector is not a fence"
                        .to_owned(),
                ));
            }
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        };
        let header = table
            .get(SPOOL_HEADER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .ok_or_else(|| SpoolError::Corrupt("spool header is missing".to_owned()))?;
        let header = decode_header(header.value())?;
        let entries = collect_entries(&table)?;
        validate_header(&header, &entries)?;
        let high_water = read.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!("high-water metadata is unavailable: {error}"))
        })?;
        let high_water = read_high_water(&high_water)?
            .ok_or_else(|| SpoolError::Corrupt("high-water metadata is missing".to_owned()))?;
        validate_high_water(&header, &entries, high_water)?;
        // The work ceiling is consulted against the real retained member count
        // rather than only shape-validated, so a capture over an over-limit or
        // corrupt spool fails closed here instead of reading an unbounded set.
        // It is a safety net, not a binding production bound: the owner port
        // admits `max_work_units == BACKUP_MAX_WORK_UNITS`, which equals the
        // `SPOOL_MAX_RECORDS` retention ceiling this same spool enforces, so for
        // an admitted capture the comparison can only trip when the retained
        // set is itself over the ceiling.
        let capture_work = u64::try_from(entries.len()).map_err(|_| {
            SpoolError::Corrupt(
                "watchdog spool backup capture work exceeds the bounded counter".to_owned(),
            )
        })?;
        if capture_work > limits.max_work_units {
            return Err(SpoolError::Corrupt(
                "watchdog spool backup capture exceeds the bounded work ceiling".to_owned(),
            ));
        }
        backup::capture_fence(&header, &entries, high_water, &params)
    }

    /// Imports an isolated-restore step chain as quarantined historical evidence.
    ///
    /// Gates the destination triple through
    /// [`backup::validate_isolated_destination`] (the destination must differ
    /// from both the source and the active installation) and the chain through
    /// [`backup::validate_restore_chain`], rooted at the admitted preparation
    /// digest carried as the first step's predecessor. Each accepted step is
    /// appended through the existing [`append`](Self::append) path as a
    /// `Recovery` record naming the exact source installation with the step
    /// digest as evidence; such records grant no lease, heartbeat, supervision
    /// authority, or epoch, and keep the coverage denominator incomplete until
    /// reconciled. Idempotency follows [`backup::SpoolImportReplayLedger`]
    /// semantics plus the durable quarantine framing: a byte-identical repeat
    /// observes `Duplicate` and appends nothing, while changed content under an
    /// observed operation identity fails closed as [`SpoolError::Corrupt`]. At
    /// most one bounded step per [`backup::BACKUP_MAX_WORK_UNITS`] work unit is
    /// admitted, each appended in its own bounded write transaction; no
    /// restart, deletion, overwrite, or cutover is performed.
    ///
    /// Known limitation (unresolved, not claimed as admission): the accepted
    /// step is appended to **this** owner spool, which is the currently active
    /// installation's spool. The destination triple is validated and then
    /// discarded; no admitted isolated destination spool is opened or written.
    /// This owner has no constructor that accepts an externally admitted
    /// destination installation binding, so writing into one would require
    /// inventing an admission that does not exist here. The consequence is
    /// bounded and non-authoritative — the rows are quarantined historical
    /// `Recovery` markers carrying no active lease, heartbeat, supervision, or
    /// epoch authority — but they are **not** in the isolated destination, and
    /// this method therefore does not yet perform an isolated-destination
    /// import. See the #945 final composition for the admitted destination.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the destination is not isolated, the step
    /// chain is empty, malformed, non-consecutive, or unlinked, the bounded
    /// step count is exceeded, or any step conflicts with already quarantined
    /// evidence.
    pub fn import_backup_isolated(
        &self,
        source_installation: &str,
        dest_installation: &str,
        active_installation: &str,
        steps: &[backup::SpoolRestoreStep],
    ) -> Result<backup::SpoolRestoreDisposition, SpoolError> {
        backup::validate_isolated_destination(
            source_installation,
            dest_installation,
            active_installation,
        )?;
        let step_count = u64::try_from(steps.len()).map_err(|_| {
            SpoolError::Corrupt(
                "watchdog spool backup import exceeds the bounded step counter".to_owned(),
            )
        })?;
        if step_count > backup::BACKUP_MAX_WORK_UNITS {
            return Err(SpoolError::Corrupt(
                "watchdog spool backup import exceeds the bounded work ceiling".to_owned(),
            ));
        }
        let prepare_digest = steps
            .first()
            .map_or("", |step| step.predecessor_digest.as_str());
        backup::validate_restore_chain(prepare_digest, steps)?;
        let retained = self.readback()?;
        let mut quarantined: Vec<(String, String)> = Vec::new();
        for entry in &retained {
            if let WatchdogSpoolPayload::Recovery {
                reason,
                corrupt_digest,
                ..
            } = &entry.payload
                && reason.starts_with(BACKUP_IMPORT_REASON_MARKER)
            {
                quarantined.push((reason.clone(), corrupt_digest.clone()));
            }
        }
        let observed_at_ms = current_unix_ms()?.max(1);
        let mut ledger = backup::SpoolImportReplayLedger::new();
        let mut disposition = backup::SpoolRestoreDisposition::Duplicate;
        for step in steps {
            match ledger.observe(&step.operation_id, &step.step_digest)? {
                backup::SpoolImportReplayDisposition::Duplicate => continue,
                backup::SpoolImportReplayDisposition::Accepted => {}
            }
            let reason = Self::backup_import_reason(
                source_installation,
                &step.operation_id,
                step.step_index,
            );
            if let Some((_, known_digest)) = quarantined.iter().find(|(known, _)| known == &reason)
            {
                if known_digest != &step.step_digest {
                    return Err(SpoolError::Corrupt(
                        "watchdog spool backup replay identity conflicts with changed content"
                            .to_owned(),
                    ));
                }
                continue;
            }
            let operation_prefix =
                Self::backup_import_operation_prefix(source_installation, &step.operation_id);
            if quarantined
                .iter()
                .any(|(known, _)| known.starts_with(&operation_prefix) && known != &reason)
            {
                return Err(SpoolError::Corrupt(
                    "watchdog spool backup replay identity conflicts with changed content"
                        .to_owned(),
                ));
            }
            self.append(
                observed_at_ms,
                WatchdogSpoolPayload::Recovery {
                    service: SERVICE_NAME.to_owned(),
                    reason: reason.clone(),
                    corrupt_sequence: None,
                    corrupt_digest: step.step_digest.clone(),
                },
            )?;
            quarantined.push((reason, step.step_digest.clone()));
            disposition = backup::SpoolRestoreDisposition::Accepted;
        }
        Ok(disposition)
    }

    /// Builds the exact quarantine reason for one imported restore step.
    ///
    /// The framing binds the fixed marker, the exact source installation, the
    /// stable operation identity, and the step index; all inputs are already
    /// validated (non-blank, control-free, bounded) so the reason always
    /// satisfies the backup text bound.
    fn backup_import_reason(
        source_installation: &str,
        operation_id: &str,
        step_index: u64,
    ) -> String {
        format!(
            "{BACKUP_IMPORT_REASON_MARKER} from {source_installation} operation {operation_id} step {step_index}"
        )
    }

    /// Builds the quarantine reason prefix for one import operation identity.
    ///
    /// Any retained quarantined reason with this prefix but a different full
    /// reason is changed content under the same operation identity.
    fn backup_import_operation_prefix(source_installation: &str, operation_id: &str) -> String {
        format!(
            "{BACKUP_IMPORT_REASON_MARKER} from {source_installation} operation {operation_id} step "
        )
    }

    pub(crate) fn initialize_or_recover(&self) -> Result<(), SpoolError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let table = match read.open_table(SPOOL_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                drop(read);
                return self.write_header(&WatchdogSpoolHeader {
                    schema_version: SPOOL_SCHEMA_VERSION,
                    next_sequence: 1,
                    first_sequence: 1,
                    record_count: 0,
                    bytes: 0,
                });
            }
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        };
        let header = table
            .get(SPOOL_HEADER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let entries = collect_entries(&table);
        let parsed_header = header
            .as_ref()
            .and_then(|value| decode_header(value.value()).ok());
        let high_water_table = match read.open_table(SPOOL_HIGH_WATER_TABLE) {
            Ok(table) => Some(table),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        };
        let parsed_high_water = high_water_table
            .as_ref()
            .map(read_high_water)
            .transpose()?
            .flatten();
        let header_and_entries_valid = parsed_header
            .as_ref()
            .zip(entries.as_ref().ok())
            .is_some_and(|(header, entries)| validate_header(header, entries).is_ok());
        let valid = header_and_entries_valid
            && parsed_high_water.is_some_and(|high_water| {
                parsed_header
                    .as_ref()
                    .zip(entries.as_ref().ok())
                    .is_some_and(|(header, entries)| {
                        validate_high_water(header, entries, high_water).is_ok()
                    })
            });
        if valid {
            return self.ensure_export_cursor();
        }
        if header_and_entries_valid
            && let Some(high_water) = parsed_high_water
            && let Some((header, entries)) = parsed_header.as_ref().zip(entries.as_ref().ok())
        {
            validate_high_water(header, entries, high_water)?;
        }
        let corrupt_digest = header
            .as_ref()
            .map_or_else(|| "missing".to_owned(), |value| sha256_hex(value.value()));
        drop(table);
        drop(read);
        self.recover(
            "existing spool header or record set failed validation",
            None,
            corrupt_digest,
        )
    }

    fn write_header(&self, header: &WatchdogSpoolHeader) -> Result<(), SpoolError> {
        let bytes = encode_header(header)?;
        let high_water = header.next_sequence.saturating_sub(1);
        let high_water_bytes = encode_high_water(high_water)?;
        // A fresh spool has acknowledged nothing. The cursor row starts
        // unbound (zero generation, empty identities); the first export binds
        // the caller identities in memory and the first acknowledgement
        // persists them, so no canned identity is ever invented here.
        let cursor_bytes = encode_export_cursor(&unbound_export_cursor())?;
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        {
            let mut table = write
                .open_table(SPOOL_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            table
                .insert(SPOOL_HEADER_KEY, bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            drop(table);
            let mut high_water_table = write
                .open_table(SPOOL_HIGH_WATER_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            high_water_table
                .insert(SPOOL_HIGH_WATER_KEY, high_water_bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            drop(high_water_table);
            let mut cursor_table = write
                .open_table(SPOOL_EXPORT_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            cursor_table
                .insert(SPOOL_EXPORT_CURSOR_KEY, cursor_bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            drop(cursor_table);
        }
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))
    }

    fn recover(
        &self,
        reason: &str,
        corrupt_sequence: Option<u64>,
        corrupt_digest: String,
    ) -> Result<(), SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let mut high_water_table = write.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!(
                "high-water metadata is missing; sequence continuity cannot be proven: {error}"
            ))
        })?;
        let previous_high_water = high_water_table
            .get(SPOOL_HIGH_WATER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| {
                SpoolError::Corrupt(
                    "high-water metadata is missing; sequence continuity cannot be proven"
                        .to_owned(),
                )
            })?;
        let previous_high_water = decode_high_water(&previous_high_water)?;
        let recovery_sequence = previous_high_water
            .checked_add(1)
            .ok_or_else(|| SpoolError::Corrupt("spool sequence exhausted".to_owned()))?;
        // Preserve-then-clamp: a restart keeps the stored cursor. See
        // `preserved_export_cursor_bytes` for the exact guarantee.
        let preserved_cursor_bytes = preserved_export_cursor_bytes(&write, recovery_sequence)?;
        let entry = WatchdogSpoolEntry {
            schema_version: SPOOL_SCHEMA_VERSION,
            sequence: recovery_sequence,
            observed_at_ms: current_unix_ms()?.max(1),
            payload: WatchdogSpoolPayload::Recovery {
                service: SERVICE_NAME.to_owned(),
                reason: reason.to_owned(),
                corrupt_sequence,
                corrupt_digest,
            },
        };
        let bytes = encode_entry(&entry)?;
        let header = WatchdogSpoolHeader {
            schema_version: SPOOL_SCHEMA_VERSION,
            next_sequence: recovery_sequence
                .checked_add(1)
                .ok_or_else(|| SpoolError::Corrupt("spool sequence exhausted".to_owned()))?,
            first_sequence: recovery_sequence,
            record_count: 1,
            bytes: bytes.len() as u64,
        };
        let header_bytes = encode_header(&header)?;
        {
            let mut table = write
                .open_table(SPOOL_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            let keys = table
                .iter()
                .map_err(|error| SpoolError::Database(error.to_string()))?
                .map(|item| {
                    item.map(|(key, _)| key.value())
                        .map_err(|error| SpoolError::Database(error.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if keys
                .iter()
                .filter(|key| **key != SPOOL_HEADER_KEY)
                .any(|key| *key > previous_high_water)
            {
                return Err(SpoolError::Corrupt(
                    "high-water metadata is below a retained sequence; continuity cannot be proven"
                        .to_owned(),
                ));
            }
            for key in keys {
                table
                    .remove(key)
                    .map_err(|error| SpoolError::Database(error.to_string()))?;
            }
            table
                .insert(SPOOL_HEADER_KEY, header_bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            table
                .insert(entry.sequence, bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            let high_water_bytes = encode_high_water(recovery_sequence)?;
            high_water_table
                .insert(SPOOL_HIGH_WATER_KEY, high_water_bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            drop(table);
            store_export_cursor_bytes(&write, &preserved_cursor_bytes)?;
        }
        drop(high_water_table);
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))
    }

    /// Appends one payload to the retained spool in its own bounded write
    /// transaction.
    ///
    /// This is the ordinary record path. A caller that must commit a record
    /// together with other durable state uses
    /// [`Self::append_in_transaction`] instead, so the record and that state
    /// share one owner transaction rather than a nested write.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the retained spool, header, or high-water
    /// fails validation, the sequence is exhausted or drifts, or the write
    /// cannot be committed.
    pub(crate) fn append(
        &self,
        observed_at_ms: u64,
        payload: WatchdogSpoolPayload,
    ) -> Result<SpoolAppendOutcome, SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let (outcome, _created) = Self::append_in_transaction(&write, observed_at_ms, payload)?;
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        Ok(outcome)
    }

    /// Appends one payload inside an already-open write transaction and returns
    /// the exact entry that was created, together with the retention outcome.
    ///
    /// The returned entry is the appended payload's own record, not a later read
    /// of the spool high-water mark and not the retention-pressure gap record
    /// that may precede it: when retention pressure applies, this writes the
    /// extra pressure-gap record and then the payload, and returns the payload
    /// entry. A caller can therefore name the record it just created without an
    /// interleaved append being able to substitute another entry's identity.
    ///
    /// Nothing is committed here. The caller owns the transaction, so a failure
    /// before its commit leaves the whole retained spool and any other state it
    /// wrote exactly as it was.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the retained spool, header, or high-water
    /// fails validation, the sequence is exhausted or drifts, or the record
    /// cannot be encoded.
    #[allow(
        clippy::too_many_lines,
        reason = "bounded spool retention, pressure marking, and high-water updates stay one atomic redb transaction"
    )]
    fn append_in_transaction(
        write: &WriteTransaction,
        observed_at_ms: u64,
        payload: WatchdogSpoolPayload,
    ) -> Result<(SpoolAppendOutcome, WatchdogSpoolEntry), SpoolError> {
        let mut table = write
            .open_table(SPOOL_TABLE)
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let mut high_water_table = write.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!(
                "high-water metadata is unavailable; sequence continuity cannot be proven: {error}"
            ))
        })?;
        let header_bytes = table
            .get(SPOOL_HEADER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| SpoolError::Corrupt("spool header is missing".to_owned()))?;
        let mut header = decode_header(&header_bytes)?;
        let entries = collect_entries(&table)?;
        validate_header(&header, &entries)?;
        let high_water = high_water_table
            .get(SPOOL_HIGH_WATER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| {
                SpoolError::Corrupt(
                    "high-water metadata is missing; sequence continuity cannot be proven"
                        .to_owned(),
                )
            })?;
        let high_water = decode_high_water(&high_water)?;
        validate_high_water(&header, &entries, high_water)?;
        let sequence = high_water
            .checked_add(1)
            .ok_or_else(|| SpoolError::Corrupt("spool sequence exhausted".to_owned()))?;
        if sequence != header.next_sequence {
            return Err(SpoolError::Corrupt(
                "spool header next sequence does not match high-water metadata".to_owned(),
            ));
        }
        let entry = WatchdogSpoolEntry {
            schema_version: SPOOL_SCHEMA_VERSION,
            sequence,
            observed_at_ms,
            payload: payload.clone(),
        };
        let initial_bytes = encode_entry(&entry)?;
        let pressure = header.record_count >= SPOOL_MAX_RECORDS
            || header.bytes.saturating_add(initial_bytes.len() as u64) > SPOOL_MAX_BYTES;
        let (encoded_entries, created_entry) = if pressure {
            let marker = WatchdogSpoolEntry {
                schema_version: SPOOL_SCHEMA_VERSION,
                sequence,
                observed_at_ms,
                payload: WatchdogSpoolPayload::Gap {
                    service: SERVICE_NAME.to_owned(),
                    reason: crate::GapRecoveryReason::SpoolPressure,
                    coverage_claimed: false,
                },
            };
            let entry_sequence = sequence
                .checked_add(1)
                .ok_or_else(|| SpoolError::Corrupt("spool sequence overflow".to_owned()))?;
            let entry = WatchdogSpoolEntry {
                schema_version: SPOOL_SCHEMA_VERSION,
                sequence: entry_sequence,
                observed_at_ms,
                payload,
            };
            let created = entry.clone();
            (
                vec![
                    (sequence, encode_entry(&marker)?),
                    (entry_sequence, encode_entry(&entry)?),
                ],
                created,
            )
        } else {
            (vec![(sequence, initial_bytes)], entry)
        };
        let total_bytes = encoded_entries
            .iter()
            .map(|(_, bytes)| bytes.len() as u64)
            .sum::<u64>();
        let mut evicted_records = 0;
        while header.record_count + encoded_entries.len() as u64 > SPOOL_MAX_RECORDS
            || header.bytes.saturating_add(total_bytes) > SPOOL_MAX_BYTES
        {
            if header.record_count == 0 {
                break;
            }
            let old_sequence = header.first_sequence;
            let old = table
                .remove(old_sequence)
                .map_err(|error| SpoolError::Database(error.to_string()))?
                .ok_or_else(|| SpoolError::Corrupt("retention record is missing".to_owned()))?;
            header.bytes = header
                .bytes
                .checked_sub(old.value().len() as u64)
                .ok_or_else(|| SpoolError::Corrupt("spool byte counter underflow".to_owned()))?;
            header.first_sequence = old_sequence
                .checked_add(1)
                .ok_or_else(|| SpoolError::Corrupt("spool sequence overflow".to_owned()))?;
            header.record_count -= 1;
            evicted_records += 1;
        }
        for (sequence, bytes) in &encoded_entries {
            table
                .insert(*sequence, bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            if header.record_count == 0 {
                header.first_sequence = *sequence;
            }
            header.record_count += 1;
            header.bytes = header
                .bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| SpoolError::Corrupt("spool byte counter overflow".to_owned()))?;
        }
        header.schema_version = SPOOL_SCHEMA_VERSION;
        let last_sequence = encoded_entries
            .last()
            .map(|(sequence, _)| *sequence)
            .ok_or_else(|| SpoolError::Corrupt("spool append produced no records".to_owned()))?;
        header.next_sequence = last_sequence
            .checked_add(1)
            .ok_or_else(|| SpoolError::Corrupt("spool sequence overflow".to_owned()))?;
        let header_bytes = encode_header(&header)?;
        table
            .insert(SPOOL_HEADER_KEY, header_bytes.as_slice())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let high_water_bytes = encode_high_water(last_sequence)?;
        high_water_table
            .insert(SPOOL_HIGH_WATER_KEY, high_water_bytes.as_slice())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        drop(table);
        drop(high_water_table);
        let outcome = if pressure {
            SpoolAppendOutcome::Pressure { evicted_records }
        } else {
            SpoolAppendOutcome::Stored
        };
        Ok((outcome, created_entry))
    }

    /// Reads the durable high-water sequence without mutating any spool state.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the database cannot be read or the
    /// high-water metadata is absent or invalid.
    pub(crate) fn high_water_sequence(&self) -> Result<u64, SpoolError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let table = read.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!("high-water metadata is unavailable: {error}"))
        })?;
        read_high_water(&table)?
            .ok_or_else(|| SpoolError::Corrupt("high-water metadata is missing".to_owned()))
    }

    /// Counts one genuinely observed Governor-unavailability proof and commits a
    /// spooled intent when the Watchdog-owned deterministic rule reaches a
    /// configured threshold.
    ///
    /// The proof is the only input: it is minted from a real admission-path or
    /// kernel-supervision rejection, never from a caller-chosen reason, so
    /// retention pressure and host-identity observations can never mint. The
    /// rule reads and rewrites its durable episode state in `watchdog.redb`, so
    /// a restart cannot reset the threshold, and only
    /// [`Self::observe_governor_recovery`] closes an open episode.
    ///
    /// Rule advancement and emission are one owner transaction. The expected
    /// rule state is read and validated inside a single write transaction, one
    /// observation is applied to it, any threshold intent is appended through
    /// [`Self::append_in_transaction`] — never through a nested write — and the
    /// advancement, the emission reference naming that exact created entry, and
    /// the spool's own high-water updates all commit together. A failure before
    /// that commit therefore leaves the old coherent state with no appended
    /// record, and the returned identity always names the record this call
    /// actually created rather than a later read of the global high-water mark.
    ///
    /// When the commit outcome is uncertain, the call reconciles the original
    /// observation by its own preserved identity before deciding: if that
    /// observation's emission is durable it returns that emission, and if it is
    /// not, it reports the failure. Neither outcome can mint a second threshold
    /// record for the same observation, so a retry reconciles rather than
    /// remints.
    ///
    /// A replay of an admitted source observation that already crossed a
    /// threshold reconciles that episode's existing emission and creates no
    /// record. Emission is not episode closure: the episode stays open and keeps
    /// counting toward the next threshold, and after the Incident threshold it
    /// stays explicitly escalated while further failures produce bounded
    /// non-emitting outcomes.
    ///
    /// The append is the only write: no ORS, canonical, or `HostStateJournal`
    /// write is reachable from this path.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the rule state or the record fails
    /// validation, the episode state is not canonical for this observation, the
    /// threshold evidence would exceed the bounded frame, or the spool cannot be
    /// read or written.
    pub(crate) fn observe_governor_unavailability(
        &self,
        proof: intent::GovernorUnavailability,
        observation_digest: &str,
        lineage: intent::IntentLineage,
        observed_at_ms: u64,
    ) -> Result<intent::GovernorIntentOutcome, SpoolError> {
        let producer_generation = lineage.watchdog_generation();
        let reason = proof.reason();
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let mut state = Self::read_intent_rule_state_in(&write)?;
        let crossing = match state.classify_observation(observation_digest) {
            intent::GovernorIntentObservationClass::AlreadyCommitted {
                intent_class,
                emission,
            } => {
                // The same admitted source observation already crossed this
                // threshold and its record is durable. Reconcile that exact
                // record; the transaction wrote nothing, so it is rolled back.
                drop(write);
                return Ok(Self::committed_intent_outcome(intent_class, &emission));
            }
            intent::GovernorIntentObservationClass::AlreadyCounted => {
                // Already counted inside this episode, so it is not a further
                // failure. Nothing advances and nothing is minted.
                drop(write);
                return Ok(intent::GovernorIntentOutcome::Counting {
                    consecutive: state.threshold_progress_observations,
                });
            }
            intent::GovernorIntentObservationClass::Observed => None,
            intent::GovernorIntentObservationClass::ThresholdCrossing { intent_class } => {
                Some(intent_class)
            }
        };
        let mut emission = None;
        if let Some(intent_class) = crossing {
            emission = Some(Self::commit_threshold_intent(
                &write,
                &state,
                intent_class,
                proof,
                observation_digest,
                lineage,
                observed_at_ms,
            )?);
        }
        state.record_observation(intent::GovernorIntentObservationRecord {
            observation_digest: observation_digest.to_owned(),
            reason,
            observed_at_ms,
            producer_generation,
            emission: emission.clone(),
        })?;
        Self::write_intent_rule_state_in(&write, &state)?;
        let emitted = match write.commit() {
            Ok(()) => emission,
            Err(error) => {
                // The commit outcome is uncertain: it may or may not have
                // applied. Reconcile this observation by its own identity before
                // deciding, so the caller can never be handed a second threshold
                // record for an observation that already has one.
                match self.reconcile_committed_emission(observation_digest) {
                    Some(reconciled) => Some(reconciled),
                    None => return Err(SpoolError::Database(error.to_string())),
                }
            }
        };
        Ok(match emitted {
            Some((intent_class, emitted)) => {
                tracing::debug!(
                    event = "watchdog.intent_spooled",
                    observation = "committed",
                    sequence = emitted.sequence,
                    intent_kind = intent_class.as_str(),
                    episode_closed = false,
                    "watchdog committed a non-semantic intent record and its episode reference in one owner transaction; the episode stays open"
                );
                Self::committed_intent_outcome(intent_class, &emitted)
            }
            None => intent::GovernorIntentOutcome::Counting {
                consecutive: state.threshold_progress_observations,
            },
        })
    }

    /// Appends the threshold intent this crossing observation committed, inside
    /// the caller's already-open transaction, and returns the emission bound to
    /// the exact record it created.
    ///
    /// Nothing here commits: the caller owns the single transaction that carries
    /// rule advancement, the intent record and its high-water together.
    fn commit_threshold_intent(
        write: &redb::WriteTransaction,
        state: &intent::GovernorIntentRuleState,
        intent_class: intent::WatchdogIntentClass,
        proof: intent::GovernorUnavailability,
        observation_digest: &str,
        lineage: intent::IntentLineage,
        observed_at_ms: u64,
    ) -> Result<(intent::WatchdogIntentClass, intent::GovernorIntentEmission), SpoolError> {
        // The recording generation is the lineage's own, so it is read here
        // rather than passed alongside it: one source, not two that can disagree.
        let producer_generation = lineage.watchdog_generation();
        // The threshold evidence of the episode including this crossing
        // observation: exactly one digest per unit of threshold progress,
        // and never more than the bounded evidence frame.
        let mut evidence_refs = state.episode_evidence_refs();
        evidence_refs.push(observation_digest.to_owned());
        if evidence_refs.len() > intent::MAX_INTENT_EVIDENCE_REFS {
            return Err(SpoolError::Corrupt(
                "watchdog intent episode threshold evidence exceeds the bounded frame".to_owned(),
            ));
        }
        let payload = match intent_class {
            intent::WatchdogIntentClass::Problem => intent::ProblemIntentRecord::new(
                proof,
                SERVICE_NAME.to_owned(),
                evidence_refs,
                lineage,
                observed_at_ms,
            )?
            .to_payload(),
            intent::WatchdogIntentClass::Incident => intent::IncidentIntentRecord::new(
                proof,
                SERVICE_NAME.to_owned(),
                evidence_refs,
                lineage,
                observed_at_ms,
            )?
            .to_payload(),
        };
        let (_outcome, created) = Self::append_in_transaction(write, observed_at_ms, payload)?;
        // The identity of the record this transaction just created, bound the
        // same way an export batch binds it. A retention-pressure gap record
        // written ahead of it can never be mistaken for the intent, and an
        // interleaved append can never substitute another entry's sequence.
        let raw = encode_entry(&created)?;
        let (_payload_digest, record_digest) = export_record_digests(&created, &raw);
        Ok((
            intent_class,
            intent::GovernorIntentEmission {
                sequence: created.sequence,
                record_digest,
                observation_digest: observation_digest.to_owned(),
                observed_at_ms,
                producer_generation,
            },
        ))
    }

    /// Projects one already-committed threshold emission onto its outcome.
    fn committed_intent_outcome(
        intent_class: intent::WatchdogIntentClass,
        emission: &intent::GovernorIntentEmission,
    ) -> intent::GovernorIntentOutcome {
        let reference = intent::WatchdogIntentRecordRef {
            sequence: emission.sequence,
            intent_class,
            observed_at_ms: emission.observed_at_ms,
            record_digest: emission.record_digest.clone(),
        };
        match intent_class {
            intent::WatchdogIntentClass::Problem => {
                intent::GovernorIntentOutcome::ProblemIntent(reference)
            }
            intent::WatchdogIntentClass::Incident => {
                intent::GovernorIntentOutcome::IncidentIntent(reference)
            }
        }
    }

    /// Reconciles the emission a rule row already holds for exactly this
    /// admitted source observation.
    fn reconcile_committed_emission(
        &self,
        observation_digest: &str,
    ) -> Option<(intent::WatchdogIntentClass, intent::GovernorIntentEmission)> {
        self.read_intent_rule_state()
            .ok()
            .and_then(|state| state.committed_emission(observation_digest))
    }

    /// Closes an open deterministic-rule episode after a live Governor
    /// admission, and returns whether an episode was actually closed.
    ///
    /// A live admission is the only recovery signal the rule accepts: it never
    /// resets on a timer, on a restart, on an export acknowledgement, or on a
    /// caller-chosen reason. `presenting_generation` is the Watchdog generation
    /// of that admission, and a recovery presented by a generation older than
    /// the one that last advanced the episode is refused as obsolete, so a late
    /// success from a superseded admission generation cannot close it.
    ///
    /// Recovery is serialized against observations under the same writer
    /// discipline: the episode and its revision are re-read and re-validated
    /// inside one write transaction, and a recovery that predates the newest
    /// accepted outage observation is refused, so a later recovery can neither
    /// silently overwrite a concurrently accepted newer observation nor report a
    /// refusal as a closure.
    ///
    /// Closing withdraws nothing. It claims no canonical resolution: the
    /// episode's spooled intents stay retained and unacknowledged until the
    /// fenced Kernel route reconciles them, and it never touches their records,
    /// their submit-once receipts, or the spool itself.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the rule state is not canonical, the recovery
    /// identity is uninitialized, or the state cannot be written.
    pub(crate) fn observe_governor_recovery(
        &self,
        presenting_generation: u64,
        observed_at_ms: u64,
    ) -> Result<bool, SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let mut state = Self::read_intent_rule_state_in(&write)?;
        let closed_episode_id = match state.close_episode(presenting_generation, observed_at_ms)? {
            // Nothing changed in either case, so the uncommitted transaction is
            // dropped and the caller is told no episode was closed by this call.
            intent::GovernorEpisodeClosure::AlreadyClosed
            | intent::GovernorEpisodeClosure::Obsolete => {
                drop(write);
                return Ok(false);
            }
            intent::GovernorEpisodeClosure::Closed { episode_id } => episode_id,
        };
        Self::write_intent_rule_state_in(&write, &state)?;
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        tracing::debug!(
            event = "watchdog.intent_episode_closed",
            observation = "reconciled",
            episode = closed_episode_id.as_str(),
            "live Governor admission closed one open watchdog intent episode; its unacknowledged intents stay retained"
        );
        Ok(true)
    }

    /// Returns a bounded window of retained Watchdog intents that have no
    /// submit-once receipt, oldest first.
    ///
    /// Read-only: nothing is submitted, reserved, or removed here. Each entry
    /// carries the exact original record plus the same record and payload
    /// digests the export batch binds, so the fenced Kernel route can prove the
    /// presented bytes are the retained Watchdog record, plus the Watchdog's own
    /// epoch lineage so the durable intent record can be stamped with stable
    /// observation lineage. An empty result means every retained intent already
    /// holds a submit-once receipt.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the retained spool, header, or high-water
    /// fails validation, the window bound is zero, or a stored submit-once
    /// receipt is not canonical.
    pub(crate) fn pending_watchdog_intents(
        &self,
        limit: usize,
        epoch_lineage: &eliot_contracts::EpochLineageId,
    ) -> Result<Vec<intent::PendingWatchdogIntent>, SpoolError> {
        if limit == 0 || limit > intent::INTENT_RECONCILIATION_MAX_SUBMISSIONS {
            return Err(SpoolError::Corrupt(
                "watchdog intent reconciliation window is outside its bounded range".to_owned(),
            ));
        }
        let (entries, _high_water, _cursor) = self.read_export_snapshot()?;
        let submitted = self.read_intent_receipt_sequences()?;
        let mut pending = Vec::new();
        for entry in &entries {
            if pending.len() >= limit {
                break;
            }
            if !intent::is_intent_payload(&entry.payload) || submitted.contains(&entry.sequence) {
                continue;
            }
            let raw = encode_entry(entry)?;
            let (payload_digest, record_digest) = export_record_digests(entry, &raw);
            pending.push(intent::PendingWatchdogIntent {
                record: entry.clone(),
                intent_class: intent::WatchdogIntentClass::of_payload(&entry.payload)?,
                record_digest,
                payload_digest,
                epoch_lineage: epoch_lineage.clone(),
            });
        }
        Ok(pending)
    }

    /// Persists the durable submit-once receipt for one reconciled intent.
    ///
    /// This is the exactly-once boundary of fenced-Kernel reconciliation, and
    /// its scope is one retained spool record. A first call for a retained
    /// sequence writes the receipt and reports
    /// [`IntentSubmissionDisposition::Recorded`]. Any later call for the same
    /// sequence observes [`IntentSubmissionDisposition::AlreadySubmitted`]
    /// without writing, which is what a retry after a lost acknowledgement must
    /// see. A repeated call that carries a different reconciliation key or a
    /// different acknowledgement digest is an identity conflict and fails closed
    /// instead of overwriting the ledger.
    ///
    /// It is not episode-level deduplication and not a canonical-resolution
    /// claim: how many intents an episode mints is the rule's own decision, and
    /// a committed receipt says the fenced Kernel accepted this one record, not
    /// that the Governor transitioned anything.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the receipt is not canonical, an existing
    /// receipt for the same sequence disagrees, or the ledger cannot be
    /// written.
    pub(crate) fn record_intent_submission(
        &self,
        submission: &intent::WatchdogIntentSubmission,
    ) -> Result<intent::IntentSubmissionDisposition, SpoolError> {
        validate_intent_submission_receipt(submission)?;
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let existing = {
            let table = write
                .open_table(SPOOL_INTENT_RECEIPT_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            table
                .get(submission.sequence)
                .map_err(|error| SpoolError::Database(error.to_string()))?
                .map(|value| decode_intent_receipt(value.value()))
                .transpose()?
        };
        if let Some(stored) = existing {
            if stored.idempotency_key != submission.idempotency_key
                || stored.acknowledgement_digest != submission.acknowledgement_digest
            {
                return Err(SpoolError::Corrupt(
                    "watchdog intent submit-once receipt conflicts with a changed reconciliation identity"
                        .to_owned(),
                ));
            }
            return Ok(intent::IntentSubmissionDisposition::AlreadySubmitted);
        }
        {
            let mut table = write
                .open_table(SPOOL_INTENT_RECEIPT_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            table
                .insert(
                    submission.sequence,
                    encode_intent_receipt(submission)?.as_slice(),
                )
                .map_err(|error| SpoolError::Database(error.to_string()))?;
        }
        write
            .commit()
            .map(|()| intent::IntentSubmissionDisposition::Recorded)
            .map_err(|error| SpoolError::Database(error.to_string()))
    }

    /// Reads the durable deterministic-rule state, or the closed state of a
    /// spool that has never observed a Governor-unavailability proof.
    ///
    /// Read-only: this opens a read transaction and writes nothing, so it is the
    /// reconciliation read after an uncertain commit rather than a mutation
    /// path. A caller that is about to advance the rule uses
    /// [`Self::read_intent_rule_state_in`] inside its own write transaction
    /// instead.
    fn read_intent_rule_state(&self) -> Result<intent::GovernorIntentRuleState, SpoolError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        match read.open_table(SPOOL_INTENT_RULE_TABLE) {
            Ok(table) => table
                .get(SPOOL_INTENT_RULE_KEY)
                .map_err(|error| SpoolError::Database(error.to_string()))?
                .map(|value| decode_intent_rule_state(value.value()))
                .transpose()
                .map(|state| state.unwrap_or_else(intent::GovernorIntentRuleState::fresh)),
            Err(redb::TableError::TableDoesNotExist(_)) => {
                Ok(intent::GovernorIntentRuleState::fresh())
            }
            Err(error) => Err(SpoolError::Database(error.to_string())),
        }
    }

    /// Reads and validates the deterministic-rule state inside a caller's write
    /// transaction.
    ///
    /// Reading through the same transaction that will write the row is what
    /// makes rule advancement and the emission it mints one owner transaction:
    /// the state this call validates is the state it replaces, with no
    /// interleaved writer able to move it in between.
    fn read_intent_rule_state_in(
        write: &WriteTransaction,
    ) -> Result<intent::GovernorIntentRuleState, SpoolError> {
        match write.open_table(SPOOL_INTENT_RULE_TABLE) {
            Ok(table) => table
                .get(SPOOL_INTENT_RULE_KEY)
                .map_err(|error| SpoolError::Database(error.to_string()))?
                .map(|value| decode_intent_rule_state(value.value()))
                .transpose()
                .map(|state| state.unwrap_or_else(intent::GovernorIntentRuleState::fresh)),
            Err(redb::TableError::TableDoesNotExist(_)) => {
                Ok(intent::GovernorIntentRuleState::fresh())
            }
            Err(error) => Err(SpoolError::Database(error.to_string())),
        }
    }

    /// Persists one deterministic-rule state inside a caller's write
    /// transaction.
    ///
    /// It never opens a transaction of its own, so a caller can commit the rule
    /// advancement, the threshold intent it minted, and the spool's own
    /// high-water update as one atomic change. A failure before the caller's
    /// commit leaves the previously stored rule state exactly as it was.
    fn write_intent_rule_state_in(
        write: &WriteTransaction,
        state: &intent::GovernorIntentRuleState,
    ) -> Result<(), SpoolError> {
        state.validate()?;
        let bytes = encode_intent_rule_state(state)?;
        let mut table = write
            .open_table(SPOOL_INTENT_RULE_TABLE)
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        table
            .insert(SPOOL_INTENT_RULE_KEY, bytes.as_slice())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        Ok(())
    }

    /// Reads every retained sequence that already holds a submit-once receipt.
    fn read_intent_receipt_sequences(&self) -> Result<Vec<u64>, SpoolError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let table = match read.open_table(SPOOL_INTENT_RECEIPT_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        };
        let mut sequences = Vec::new();
        for item in table
            .iter()
            .map_err(|error| SpoolError::Database(error.to_string()))?
        {
            let (key, value) = item.map_err(|error| SpoolError::Database(error.to_string()))?;
            let receipt = decode_intent_receipt(value.value())?;
            if receipt.sequence != key.value() {
                return Err(SpoolError::Corrupt(
                    "watchdog intent submit-once receipt sequence does not match its ledger key"
                        .to_owned(),
                ));
            }
            sequences.push(receipt.sequence);
        }
        Ok(sequences)
    }

    /// Reads the stored Watchdog-owned export cursor.
    ///
    /// A spool that predates the cursor table (or has no cursor row yet)
    /// reports the unbound acknowledged-zero cursor; the first export binds
    /// the caller identities in memory and the first acknowledgement persists
    /// them. Nothing is written by this read.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the database cannot be read or a present
    /// cursor row fails strict decoding.
    pub(crate) fn read_export_cursor(&self) -> Result<WatchdogSpoolCursor, SpoolError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        match read.open_table(SPOOL_EXPORT_CURSOR_TABLE) {
            Ok(table) => decode_export_cursor_value(&table),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(unbound_export_cursor()),
            Err(error) => Err(SpoolError::Database(error.to_string())),
        }
    }

    /// Builds one bounded immutable export batch for an exact acknowledgement.
    ///
    /// The export is read-only: it never mutates the header, the high-water,
    /// or the cursor. It covers only the consecutive window starting just
    /// past the predecessor cursor, capped by both `limits` bounds, and an
    /// empty spool (`acknowledged == high-water`) yields the explicit empty
    /// batch. Spool-local intents (`ProblemIntent`, `IncidentIntent`) are
    /// ordinary covered records: the window continues past them so a retained
    /// intent can never block later observations from exporting, and
    /// [`Self::compact_below_cursor`] never removes one, so the original
    /// Watchdog record stays retained for forensic linkage with whatever the
    /// Governor later decides. Digest material carries no timestamps, so an
    /// exact retry of the same cursor, high-water, and identities is
    /// digest-equivalent.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the window is unbounded, the predecessor
    /// fails contract validation or diverges from the stored cursor, the
    /// caller high-water runs past the durable high-water, or the retained
    /// records no longer cover the cursor consecutively.
    pub(crate) fn export_batch(
        &self,
        predecessor: &WatchdogSpoolCursor,
        high_water: u64,
        limits: WatchdogSpoolExportLimits,
    ) -> Result<(WatchdogSpoolExportBatch, Vec<Vec<u8>>), SpoolError> {
        tracing::debug!(
            event = "watchdog.spool_export_attempted",
            observation = "attempted",
            "exporting spool batch without payload material"
        );
        limits.validate()?;
        validate_cursor(predecessor, high_water)?;
        let (entries, live_high_water, stored) = self.read_export_snapshot()?;
        if high_water > live_high_water {
            return Err(WatchdogSpoolReconciliationError::InvalidCursor.into());
        }
        check_export_predecessor(&stored, predecessor)?;
        if predecessor.acknowledged_sequence == high_water {
            let batch = build_empty_export_batch(predecessor, high_water)?;
            validate_batch(&batch, high_water)?;
            return Ok((batch, Vec::new()));
        }
        match select_export_window(
            &entries,
            predecessor.acknowledged_sequence,
            high_water,
            &limits,
        )? {
            ExportWindow::Ready(selected) => {
                let (batch, raws) = build_export_batch(predecessor, high_water, &selected)?;
                validate_batch(&batch, high_water)?;
                Ok((batch, raws))
            }
        }
    }

    /// Applies an exact authenticated sink acknowledgement to the cursor.
    ///
    /// The batch is revalidated against the live high-water, the batch
    /// freshness window is enforced with the owner clock, and the terminal
    /// disposition table decides through the owner-neutral core call, so
    /// `Received`, `Durable`, `AdmittedCandidate`, and `Unknown` outcomes
    /// surface as non-terminal failures and skipped gaps fail closed. Unknown
    /// outcomes, timeouts, and disconnects must never reach this method; only
    /// a complete acknowledgement for one immutable batch is applied. Inside
    /// one write transaction the stored cursor is re-read: an acknowledgement
    /// whose predecessor lies below the stored sequence is an idempotent
    /// duplicate and returns the stored sequence unchanged without writing,
    /// while any other predecessor break fails closed without writing.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] carrying the exact reconciliation failure when
    /// the batch or acknowledgement is stale, mutated, expired, non-terminal,
    /// or mismatched, and when the predecessor breaks the stored cursor.
    pub(crate) fn apply_acknowledgement(
        &self,
        batch: &WatchdogSpoolExportBatch,
        ack: &WatchdogSpoolAcknowledgement,
    ) -> Result<u64, SpoolError> {
        tracing::debug!(
            event = "watchdog.spool_ack_attempted",
            observation = "attempted",
            "applying spool acknowledgement without payload material"
        );
        let live_high_water = self.high_water_sequence()?;
        let now_ms = current_unix_ms()?;
        validate_batch(batch, live_high_water)?;
        validate_batch_freshness(batch, now_ms)?;
        validate_acknowledgement(batch, ack)?;
        let advanced = acknowledgement_advances_cursor(batch, ack)?;
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let stored = {
            let cursor_table = write
                .open_table(SPOOL_EXPORT_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            match cursor_table
                .get(SPOOL_EXPORT_CURSOR_KEY)
                .map_err(|error| SpoolError::Database(error.to_string()))?
            {
                // A missing row is a spool that predates the cursor table;
                // the first acknowledgement binds it. A present but corrupt
                // row fails closed here and heals at the next open.
                None => unbound_export_cursor(),
                Some(value) => decode_export_cursor(value.value())?,
            }
        };
        if is_duplicate_ack(stored.acknowledged_sequence, ack) {
            return Ok(stored.acknowledged_sequence);
        }
        if ack.predecessor_sequence != stored.acknowledged_sequence {
            return Err(WatchdogSpoolReconciliationError::PredecessorMismatch.into());
        }
        check_acknowledged_cursor_binding(&stored, batch)?;
        let next = WatchdogSpoolCursor {
            schema_version: SPOOL_EXPORT_CURSOR_SCHEMA_VERSION,
            acknowledged_sequence: advanced,
            watchdog_generation: batch.watchdog_generation,
            watchdog_epoch: batch.watchdog_epoch,
            installation_id: batch.installation_id.clone(),
            sink_id: batch.predecessor_cursor.sink_id.clone(),
        };
        let next_bytes = encode_export_cursor(&next)?;
        {
            let mut cursor_table = write
                .open_table(SPOOL_EXPORT_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            cursor_table
                .insert(SPOOL_EXPORT_CURSOR_KEY, next_bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            drop(cursor_table);
        }
        write
            .commit()
            .map(|()| advanced)
            .map_err(|error| SpoolError::Database(error.to_string()))
    }

    /// Compacts durably acknowledged records below the stored export cursor.
    ///
    /// This is the Wave C compaction entry point, driven by
    /// [`export_driver::export_once`](export_driver::export_once) after every
    /// successful acknowledgement (and directly by callers holding the stored
    /// acknowledged sequence). Only retained entries at or below the
    /// acknowledged sequence are candidates, and a `Gap` or `Recovery`
    /// boundary entry at or above the cursor is never removed: it is retained
    /// until a later acknowledgement advances past it. A spool-local intent is
    /// never removed at any sequence, so the original Watchdog record stays
    /// retained for forensic linkage after reconciliation. Before removing, the
    /// retained `Gap` and `Recovery` payloads are scanned and removal stops
    /// below the first unresolved marker above the cursor, so compaction can
    /// never cross an unresolved gap. The header high-water marker and
    /// `next_sequence` are never touched; only the entry rows plus the header
    /// `first_sequence`, `record_count`, and `byte` counters move, and the
    /// header is revalidated before commit.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the caller sequence differs from the
    /// stored cursor, when the stored cursor is unusable for a non-empty
    /// plan, or when the header, high-water, or counters fail validation.
    pub fn compact_below_cursor(&self, stored_cursor_acknowledged: u64) -> Result<u64, SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let mut table = write
            .open_table(SPOOL_TABLE)
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let high_water_table = write.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!(
                "high-water metadata is unavailable; sequence continuity cannot be proven: {error}"
            ))
        })?;
        let header_bytes = table
            .get(SPOOL_HEADER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| SpoolError::Corrupt("spool header is missing".to_owned()))?;
        let mut header = decode_header(&header_bytes)?;
        let entries = collect_entries(&table)?;
        validate_header(&header, &entries)?;
        let high_water_bytes = high_water_table
            .get(SPOOL_HIGH_WATER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| {
                SpoolError::Corrupt(
                    "high-water metadata is missing; sequence continuity cannot be proven"
                        .to_owned(),
                )
            })?;
        let live_high_water = decode_high_water(&high_water_bytes)?;
        validate_high_water(&header, &entries, live_high_water)?;
        let cursor_table = write
            .open_table(SPOOL_EXPORT_CURSOR_TABLE)
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let stored = match cursor_table
            .get(SPOOL_EXPORT_CURSOR_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
        {
            // A missing row means nothing was ever acknowledged; a present
            // but corrupt row fails closed and heals at the next open.
            None => unbound_export_cursor(),
            Some(value) => decode_export_cursor(value.value())?,
        };
        drop(cursor_table);
        drop(high_water_table);
        if stored_cursor_acknowledged != stored.acknowledged_sequence {
            return Err(SpoolError::Corrupt(
                "watchdog spool compaction cursor does not match the stored export cursor; refusing to compact"
                    .to_owned(),
            ));
        }
        let removable = compaction_plan(&entries, stored.acknowledged_sequence);
        if removable.is_empty() {
            return Ok(0);
        }
        if is_unbound_export_cursor(&stored) {
            return Err(SpoolError::Corrupt(
                "watchdog spool export cursor is unbound; refusing to compact".to_owned(),
            ));
        }
        validate_cursor(&stored, live_high_water)?;
        let mut removed_bytes: u64 = 0;
        let mut removed: u64 = 0;
        for sequence in &removable {
            let old = table
                .remove(*sequence)
                .map_err(|error| SpoolError::Database(error.to_string()))?
                .ok_or_else(|| SpoolError::Corrupt("retention record is missing".to_owned()))?;
            removed_bytes = removed_bytes.saturating_add(old.value().len() as u64);
            removed = removed.saturating_add(1);
        }
        header.record_count = header
            .record_count
            .checked_sub(removed)
            .ok_or_else(|| SpoolError::Corrupt("spool record counter underflow".to_owned()))?;
        header.bytes = header
            .bytes
            .checked_sub(removed_bytes)
            .ok_or_else(|| SpoolError::Corrupt("spool byte counter underflow".to_owned()))?;
        let remaining: Vec<WatchdogSpoolEntry> = entries
            .into_iter()
            .filter(|entry| !removable.contains(&entry.sequence))
            .collect();
        header.first_sequence = remaining
            .first()
            .map_or(header.next_sequence, |entry| entry.sequence);
        let header_bytes = encode_header(&header)?;
        table
            .insert(SPOOL_HEADER_KEY, header_bytes.as_slice())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        validate_header(&header, &remaining)?;
        drop(table);
        write
            .commit()
            .map(|()| removed)
            .map_err(|error| SpoolError::Database(error.to_string()))
    }

    /// Reads one validated export snapshot inside a single read transaction.
    fn read_export_snapshot(
        &self,
    ) -> Result<(Vec<WatchdogSpoolEntry>, u64, WatchdogSpoolCursor), SpoolError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let table = read.open_table(SPOOL_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!("spool export cannot open the spool table: {error}"))
        })?;
        let header_bytes = table
            .get(SPOOL_HEADER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| SpoolError::Corrupt("spool header is missing".to_owned()))?;
        let header = decode_header(&header_bytes)?;
        let entries = collect_entries(&table)?;
        validate_header(&header, &entries)?;
        let high_water_table = read.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!("high-water metadata is unavailable: {error}"))
        })?;
        let live_high_water = read_high_water(&high_water_table)?
            .ok_or_else(|| SpoolError::Corrupt("high-water metadata is missing".to_owned()))?;
        validate_high_water(&header, &entries, live_high_water)?;
        let stored = match read.open_table(SPOOL_EXPORT_CURSOR_TABLE) {
            Ok(cursor_table) => decode_export_cursor_value(&cursor_table)?,
            Err(redb::TableError::TableDoesNotExist(_)) => unbound_export_cursor(),
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        };
        Ok((entries, live_high_water, stored))
    }

    /// Backfills or heals the single-key export cursor on a valid spool.
    ///
    /// A missing row (a spool that predates the cursor table) and an
    /// undecodable row both reset to the unbound acknowledged-zero cursor.
    /// The reset direction is replay-safe: exports restart from the
    /// beginning and never skip a record, while a retention hole left by
    /// earlier pressure eviction still fails closed at export time rather
    /// than at open time.
    fn ensure_export_cursor(&self) -> Result<(), SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let needs_init = {
            let cursor_table = write
                .open_table(SPOOL_EXPORT_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            match cursor_table
                .get(SPOOL_EXPORT_CURSOR_KEY)
                .map_err(|error| SpoolError::Database(error.to_string()))?
            {
                None => true,
                Some(value) => decode_export_cursor(value.value()).is_err(),
            }
        };
        if needs_init {
            let bytes = encode_export_cursor(&unbound_export_cursor())?;
            let mut cursor_table = write
                .open_table(SPOOL_EXPORT_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            cursor_table
                .insert(SPOOL_EXPORT_CURSOR_KEY, bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            drop(cursor_table);
        }
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))
    }
}

pub(crate) fn watchdog_spool_path(watchdog_state_root: &Path) -> PathBuf {
    watchdog_state_root.join(WATCHDOG_SPOOL_FILE_NAME)
}

/// Storage encoding of the Watchdog-owned deterministic-rule state row.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct WatchdogIntentRuleStateRecord {
    schema_version: u16,
    state: intent::GovernorIntentRuleState,
}

/// Storage encoding of one superseded deterministic-rule state row.
///
/// It exists so an existing row is read strictly and then explicitly
/// dispositioned, never reinterpreted as current state and never treated as
/// fresh empty state.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct WatchdogIntentRuleStateLegacyRecord {
    schema_version: u16,
    state: intent::GovernorIntentRuleStateLegacy,
}

/// Reads only the storage revision of a stored rule row.
///
/// The row also carries the state itself, so this deliberately does not deny
/// unknown fields: it exists solely to choose the strict decoder for the exact
/// revision that was written, before any state is interpreted.
#[derive(serde::Deserialize)]
struct WatchdogIntentRuleStateRevision {
    schema_version: u16,
}

fn encode_intent_rule_state(
    state: &intent::GovernorIntentRuleState,
) -> Result<Vec<u8>, SpoolError> {
    let record = WatchdogIntentRuleStateRecord {
        schema_version: intent::INTENT_RULE_SCHEMA_VERSION,
        state: state.clone(),
    };
    serde_json::to_vec(&record).map_err(|error| SpoolError::Serialization(error.to_string()))
}

/// Decodes one stored rule row under the exact revision that wrote it.
///
/// A current row is decoded strictly and validated. A superseded row is decoded
/// strictly as the superseded shape and carried forward with an explicit
/// incomplete-history disposition. Any other revision, and any row that does not
/// decode, fails closed as corruption: neither becomes fresh empty state, and a
/// rule whose history cannot be read never silently restarts its escalation.
fn decode_intent_rule_state(bytes: &[u8]) -> Result<intent::GovernorIntentRuleState, SpoolError> {
    let revision: WatchdogIntentRuleStateRevision =
        serde_json::from_slice(bytes).map_err(|error| {
            SpoolError::Corrupt(format!("watchdog intent rule state is invalid: {error}"))
        })?;
    match revision.schema_version {
        intent::INTENT_RULE_SCHEMA_VERSION => {
            let record: WatchdogIntentRuleStateRecord =
                serde_json::from_slice(bytes).map_err(|error| {
                    SpoolError::Corrupt(format!("watchdog intent rule state is invalid: {error}"))
                })?;
            if record.state.schema_version != record.schema_version {
                return Err(SpoolError::Corrupt(
                    "watchdog intent rule state schema drifted from its storage row".to_owned(),
                ));
            }
            record.state.validate()?;
            Ok(record.state)
        }
        intent::INTENT_RULE_LEGACY_SCHEMA_VERSION => {
            let record: WatchdogIntentRuleStateLegacyRecord = serde_json::from_slice(bytes)
                .map_err(|error| {
                    SpoolError::Corrupt(format!("watchdog intent rule state is invalid: {error}"))
                })?;
            if record.state.schema_version != record.schema_version {
                return Err(SpoolError::Corrupt(
                    "watchdog intent rule state schema drifted from its storage row".to_owned(),
                ));
            }
            let state = record.state.dispositioned();
            state.validate()?;
            Ok(state)
        }
        _ => Err(SpoolError::Corrupt(format!(
            "watchdog intent rule state schema {} is unsupported",
            revision.schema_version
        ))),
    }
}

/// Storage encoding of one durable submit-once reconciliation receipt.
///
/// Mirrors [`intent::WatchdogIntentSubmission`] one to one. The ledger row key
/// is the retained Watchdog spool sequence, and the sequence is re-checked
/// against that key on every read, so a receipt can never be relocated onto a
/// different spool record.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct WatchdogIntentReceiptRecord {
    schema_version: u16,
    sequence: u64,
    idempotency_key: String,
    acknowledgement_digest: String,
    submitted_at_ms: u64,
}

fn encode_intent_receipt(
    submission: &intent::WatchdogIntentSubmission,
) -> Result<Vec<u8>, SpoolError> {
    let record = WatchdogIntentReceiptRecord {
        schema_version: INTENT_RECEIPT_SCHEMA_VERSION,
        sequence: submission.sequence,
        idempotency_key: submission.idempotency_key.clone(),
        acknowledgement_digest: submission.acknowledgement_digest.clone(),
        submitted_at_ms: submission.submitted_at_ms,
    };
    serde_json::to_vec(&record).map_err(|error| SpoolError::Serialization(error.to_string()))
}

fn decode_intent_receipt(bytes: &[u8]) -> Result<intent::WatchdogIntentSubmission, SpoolError> {
    let record: WatchdogIntentReceiptRecord = serde_json::from_slice(bytes).map_err(|error| {
        SpoolError::Corrupt(format!(
            "watchdog intent submit-once receipt is invalid: {error}"
        ))
    })?;
    if record.schema_version != INTENT_RECEIPT_SCHEMA_VERSION {
        return Err(SpoolError::Corrupt(
            "watchdog intent submit-once receipt schema is unsupported".to_owned(),
        ));
    }
    let submission = intent::WatchdogIntentSubmission {
        sequence: record.sequence,
        idempotency_key: record.idempotency_key,
        acknowledgement_digest: record.acknowledgement_digest,
        submitted_at_ms: record.submitted_at_ms,
    };
    validate_intent_submission_receipt(&submission)?;
    Ok(submission)
}

/// Fails closed on a submit-once receipt that is not in canonical form.
fn validate_intent_submission_receipt(
    submission: &intent::WatchdogIntentSubmission,
) -> Result<(), SpoolError> {
    if submission.sequence == 0 || submission.submitted_at_ms == 0 {
        return Err(SpoolError::Corrupt(
            "watchdog intent submit-once receipt carries an unusable sequence or timestamp"
                .to_owned(),
        ));
    }
    for (value, label) in [
        (&submission.idempotency_key, "reconciliation key"),
        (&submission.acknowledgement_digest, "acknowledgement digest"),
    ] {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(SpoolError::Corrupt(format!(
                "watchdog intent submit-once receipt {label} is not a lowercase SHA-256 digest"
            )));
        }
    }
    Ok(())
}

/// Storage encoding of the Watchdog-owned export cursor.
///
/// This private record exists only because the owner-neutral core contract
/// is zero-dependency and carries no `serde` implementation. It mirrors the
/// [`WatchdogSpoolCursor`] fields one to one and converts through the two
/// explicit functions below; it never shadows the core type in any API.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct WatchdogSpoolExportCursorRecord {
    schema_version: u16,
    acknowledged_sequence: u64,
    watchdog_generation: u64,
    watchdog_epoch: u64,
    installation_id: String,
    sink_id: String,
}

/// Fresh-spool cursor: nothing acknowledged and no sink bound yet.
fn unbound_export_cursor() -> WatchdogSpoolCursor {
    WatchdogSpoolCursor {
        schema_version: SPOOL_EXPORT_CURSOR_SCHEMA_VERSION,
        acknowledged_sequence: 0,
        watchdog_generation: 0,
        watchdog_epoch: 0,
        installation_id: String::new(),
        sink_id: String::new(),
    }
}

/// True while the stored cursor binds no sink identity yet.
fn is_unbound_export_cursor(cursor: &WatchdogSpoolCursor) -> bool {
    cursor.watchdog_generation == 0
        || cursor.installation_id.is_empty()
        || cursor.sink_id.is_empty()
}

/// Maps a reconciliation failure into the spool error with its exact reason.
///
/// The existing [`SpoolError`] enum gains no variant here; every contract
/// failure keeps its full core display text inside the fail-closed
/// corruption shell, which triggers no automatic recovery by itself. The
/// `?` operator applies this conversion at every validation site below.
impl From<WatchdogSpoolReconciliationError> for SpoolError {
    fn from(error: WatchdogSpoolReconciliationError) -> Self {
        Self::Corrupt(format!("watchdog spool reconciliation: {error}"))
    }
}

fn encode_export_cursor(cursor: &WatchdogSpoolCursor) -> Result<Vec<u8>, SpoolError> {
    let record = WatchdogSpoolExportCursorRecord {
        schema_version: cursor.schema_version,
        acknowledged_sequence: cursor.acknowledged_sequence,
        watchdog_generation: cursor.watchdog_generation,
        watchdog_epoch: cursor.watchdog_epoch,
        installation_id: cursor.installation_id.clone(),
        sink_id: cursor.sink_id.clone(),
    };
    serde_json::to_vec(&record).map_err(|error| SpoolError::Serialization(error.to_string()))
}

fn decode_export_cursor(bytes: &[u8]) -> Result<WatchdogSpoolCursor, SpoolError> {
    let record: WatchdogSpoolExportCursorRecord =
        serde_json::from_slice(bytes).map_err(|error| {
            SpoolError::Corrupt(format!("export cursor record is invalid: {error}"))
        })?;
    if record.schema_version != SPOOL_EXPORT_CURSOR_SCHEMA_VERSION {
        return Err(SpoolError::Corrupt(
            "export cursor record schema is unsupported".to_owned(),
        ));
    }
    if record.installation_id.len() > SPOOL_EXPORT_CURSOR_IDENTITY_MAX
        || record.sink_id.len() > SPOOL_EXPORT_CURSOR_IDENTITY_MAX
    {
        return Err(SpoolError::Corrupt(
            "export cursor record identity exceeds the bounded frame".to_owned(),
        ));
    }
    Ok(WatchdogSpoolCursor {
        schema_version: record.schema_version,
        acknowledged_sequence: record.acknowledged_sequence,
        watchdog_generation: record.watchdog_generation,
        watchdog_epoch: record.watchdog_epoch,
        installation_id: record.installation_id,
        sink_id: record.sink_id,
    })
}

/// Strictly decodes the single-key cursor row of an open read table.
///
/// A missing row reports the unbound acknowledged-zero cursor for spools
/// that predate the cursor table; a present row must decode strictly, so
/// direct readers fail closed while the open and acknowledgement paths heal
/// through their own documented reset.
fn decode_export_cursor_value<T>(table: &T) -> Result<WatchdogSpoolCursor, SpoolError>
where
    T: ReadableTable<u64, &'static [u8]>,
{
    table
        .get(SPOOL_EXPORT_CURSOR_KEY)
        .map_err(|error| SpoolError::Database(error.to_string()))?
        .map_or_else(
            || Ok(unbound_export_cursor()),
            |value| decode_export_cursor(value.value()),
        )
}

/// Reads the stored cursor and clamps it below a new recovery marker.
///
/// Recovery preserves the cursor identities verbatim and never advances past
/// them here; only the acknowledged sequence is clamped, so the cursor can
/// never jump over the recovery record. An unreadable cursor resets to the
/// unbound acknowledged-zero state, which only replays exports from the
/// start and never skips a record.
///
/// # Errors
///
/// Returns [`SpoolError`] when the cursor row cannot be read or the clamped
/// cursor cannot be encoded.
fn preserved_export_cursor_bytes(
    write: &WriteTransaction,
    recovery_sequence: u64,
) -> Result<Vec<u8>, SpoolError> {
    let cursor_table = write
        .open_table(SPOOL_EXPORT_CURSOR_TABLE)
        .map_err(|error| SpoolError::Database(error.to_string()))?;
    let stored = cursor_table
        .get(SPOOL_EXPORT_CURSOR_KEY)
        .map_err(|error| SpoolError::Database(error.to_string()))?
        .map_or_else(unbound_export_cursor, |value| {
            decode_export_cursor(value.value()).unwrap_or_else(|_| unbound_export_cursor())
        });
    drop(cursor_table);
    let preserved = WatchdogSpoolCursor {
        acknowledged_sequence: stored
            .acknowledged_sequence
            .min(recovery_sequence.saturating_sub(1)),
        ..stored
    };
    encode_export_cursor(&preserved)
}

/// Persists one cursor encoding inside the caller write transaction.
///
/// # Errors
///
/// Returns [`SpoolError`] when the cursor table cannot be written.
fn store_export_cursor_bytes(write: &WriteTransaction, bytes: &[u8]) -> Result<(), SpoolError> {
    let mut cursor_table = write
        .open_table(SPOOL_EXPORT_CURSOR_TABLE)
        .map_err(|error| SpoolError::Database(error.to_string()))?;
    cursor_table
        .insert(SPOOL_EXPORT_CURSOR_KEY, bytes)
        .map_err(|error| SpoolError::Database(error.to_string()))?;
    drop(cursor_table);
    Ok(())
}

/// Maps one spool codec payload to its owner-neutral export class.
///
/// Spool-local intents (`ProblemIntent`, `IncidentIntent`) keep the existing
/// `Recovery` (gap-like) class here: the shared `WatchdogSpoolPayloadKind` is
/// intentionally not extended (out-of-lane exhaustive matches would break).
/// The class is used for retention and compaction classification only — the
/// intent's own fenced reconciliation runs through the Kernel
/// `watchdog-spool-batch-v1` intent route, never through this tag. Compaction
/// retains every intent regardless of class, so an acknowledged intent is never
/// removed and stays linked to the Governor's decision.
fn export_payload_kind(payload: &WatchdogSpoolPayload) -> WatchdogSpoolPayloadKind {
    match payload {
        WatchdogSpoolPayload::Heartbeat { .. } => WatchdogSpoolPayloadKind::Heartbeat,
        WatchdogSpoolPayload::Gap { .. } => WatchdogSpoolPayloadKind::Gap,
        WatchdogSpoolPayload::Recovery { .. }
        | WatchdogSpoolPayload::ProblemIntent { .. }
        | WatchdogSpoolPayload::IncidentIntent { .. } => WatchdogSpoolPayloadKind::Recovery,
    }
}

/// Checks the export predecessor against the stored Watchdog-owned cursor.
///
/// An unbound stored cursor accepts any shape-valid predecessor and binds it
/// in memory; a bound cursor requires the exact acknowledged sequence plus
/// identical owner identities, including the cursor revision.
fn check_export_predecessor(
    stored: &WatchdogSpoolCursor,
    predecessor: &WatchdogSpoolCursor,
) -> Result<(), WatchdogSpoolReconciliationError> {
    if predecessor.schema_version != SPOOL_EXPORT_CURSOR_SCHEMA_VERSION
        || stored.schema_version != SPOOL_EXPORT_CURSOR_SCHEMA_VERSION
    {
        return Err(WatchdogSpoolReconciliationError::PredecessorMismatch);
    }
    if predecessor.acknowledged_sequence != stored.acknowledged_sequence {
        return Err(WatchdogSpoolReconciliationError::PredecessorMismatch);
    }
    if is_unbound_export_cursor(stored) {
        return Ok(());
    }
    if predecessor.installation_id != stored.installation_id {
        return Err(WatchdogSpoolReconciliationError::InstallationMismatch);
    }
    if predecessor.watchdog_generation != stored.watchdog_generation {
        return Err(WatchdogSpoolReconciliationError::GenerationMismatch);
    }
    if predecessor.watchdog_epoch != stored.watchdog_epoch {
        return Err(WatchdogSpoolReconciliationError::EpochMismatch);
    }
    if predecessor.sink_id != stored.sink_id {
        return Err(WatchdogSpoolReconciliationError::SinkMismatch);
    }
    Ok(())
}

/// Checks the acknowledged batch predecessor against the stored cursor.
///
/// An unbound stored cursor is bound by the first acknowledgement; a bound
/// cursor requires the exact predecessor identities the export carried.
fn check_acknowledged_cursor_binding(
    stored: &WatchdogSpoolCursor,
    batch: &WatchdogSpoolExportBatch,
) -> Result<(), WatchdogSpoolReconciliationError> {
    if is_unbound_export_cursor(stored) {
        return Ok(());
    }
    check_export_predecessor(stored, &batch.predecessor_cursor)
}

/// Outcome of the export window selection past the cursor.
///
/// Only `Ready` exists: the window always forms, and an intent inside it is an
/// ordinary covered record that the fenced Kernel intent route reconciles.
enum ExportWindow {
    Ready(Vec<(WatchdogSpoolEntry, Vec<u8>)>),
}
/// Selects the consecutive export window past the cursor under both caps.
///
/// The window starts exactly at `acknowledged + 1` and extends through the
/// smaller of the caller high-water and the item cap, stopping early at the
/// byte cap. Spool-local intents are ordinary covered records: the fenced
/// Kernel intent route reconciles them, so the window continues past an intent
/// instead of parking in front of it forever, and `compaction_plan` retains the
/// record afterwards for forensic linkage. At least one record is always
/// selected. Any retention hole inside the window fails closed instead of
/// skipping a sequence.
fn select_export_window(
    entries: &[WatchdogSpoolEntry],
    acknowledged: u64,
    high_water: u64,
    limits: &WatchdogSpoolExportLimits,
) -> Result<ExportWindow, SpoolError> {
    let first_needed = acknowledged
        .checked_add(1)
        .ok_or(WatchdogSpoolReconciliationError::PredecessorMismatch)?;
    let item_cap_end = acknowledged
        .saturating_add(limits.max_items as u64)
        .min(high_water);
    let mut selected = Vec::new();
    let mut bytes_total: u64 = 0;
    let mut expected = first_needed;
    for entry in entries
        .iter()
        .filter(|entry| entry.sequence >= first_needed && entry.sequence <= item_cap_end)
    {
        if entry.sequence != expected {
            return Err(SpoolError::Corrupt(
                "watchdog spool retention no longer covers the export cursor; refusing to skip sequences"
                    .to_owned(),
            ));
        }
        let raw = encode_entry(entry)?;
        if !selected.is_empty()
            && (selected.len() >= limits.max_items
                || bytes_total.saturating_add(raw.len() as u64) > limits.max_bytes)
        {
            break;
        }
        bytes_total = bytes_total.saturating_add(raw.len() as u64);
        // `expected` only saturates at `u64::MAX`, which no later retained
        // sequence can follow; entries are strictly increasing by header
        // validation, so the saturated value is never revisited.
        expected = expected.saturating_add(1);
        selected.push((entry.clone(), raw));
    }
    if selected.is_empty() {
        return Err(SpoolError::Corrupt(
            "watchdog spool retention no longer covers the export cursor; refusing to skip sequences"
                .to_owned(),
        ));
    }
    Ok(ExportWindow::Ready(selected))
}

/// Derives the opaque per-entry digests from the canonical entry encoding.
///
/// `payload_digest` covers the canonical entry bytes while `record_digest`
/// additionally binds the sequence identity, so a restated payload under the
/// same sequence is detectable as a digest mismatch.
fn export_record_digests(entry: &WatchdogSpoolEntry, raw: &[u8]) -> (String, String) {
    let payload_digest = sha256_hex(raw);
    let prefix = format!(
        "{}\0{}\0{}\0",
        entry.sequence, entry.schema_version, entry.observed_at_ms
    );
    let mut material = prefix.into_bytes();
    material.extend_from_slice(raw);
    (payload_digest, sha256_hex(&material))
}

/// Derives the deterministic batch identity or digest over timestamp-free
/// material.
///
/// The `NUL`-separated owner identities, range endpoints, embedded
/// high-water, and concatenated record digests fully determine the value;
/// `created_at_ms` and `expires_at_ms` are carried outside the digest so an
/// exact retry stays digest-equivalent. The domain prefix keeps the batch id
/// and the batch digest distinct values over the same fields.
fn export_batch_identity(
    predecessor: &WatchdogSpoolCursor,
    first_sequence: u64,
    last_sequence: u64,
    high_water: u64,
    record_digests: &[String],
    domain: &str,
) -> String {
    let mut material = format!(
        "{domain}\0{}\0{}\0{}\0{}\0{first_sequence}\0{last_sequence}\0{high_water}\0",
        predecessor.installation_id,
        predecessor.watchdog_generation,
        predecessor.watchdog_epoch,
        predecessor.acknowledged_sequence
    );
    for digest in record_digests {
        material.push_str(digest);
        material.push('\0');
    }
    sha256_hex(material.as_bytes())
}

/// Builds a non-empty batch over one selected window plus its raw bytes.
fn build_export_batch(
    predecessor: &WatchdogSpoolCursor,
    high_water: u64,
    selected: &[(WatchdogSpoolEntry, Vec<u8>)],
) -> Result<(WatchdogSpoolExportBatch, Vec<Vec<u8>>), SpoolError> {
    let mut export_entries = Vec::with_capacity(selected.len());
    let mut record_digests = Vec::with_capacity(selected.len());
    let mut raws = Vec::with_capacity(selected.len());
    let mut byte_size: u64 = 0;
    for (entry, raw) in selected {
        if entry.schema_version != SPOOL_EXPORT_CURSOR_SCHEMA_VERSION {
            return Err(SpoolError::Corrupt(
                "watchdog spool record schema drifted from the export contract; refusing to export"
                    .to_owned(),
            ));
        }
        let (payload_digest, record_digest) = export_record_digests(entry, raw);
        record_digests.push(record_digest.clone());
        export_entries.push(WatchdogSpoolExportEntry {
            sequence: entry.sequence,
            schema_version: entry.schema_version,
            observed_at_ms: entry.observed_at_ms,
            payload_kind: export_payload_kind(&entry.payload),
            payload_digest,
            record_digest,
        });
        byte_size = byte_size.saturating_add(raw.len() as u64);
        raws.push(raw.clone());
    }
    let first_sequence = export_entries
        .first()
        .map(|entry| entry.sequence)
        .ok_or_else(|| {
            SpoolError::Corrupt("watchdog spool export selected no records".to_owned())
        })?;
    let last_sequence = export_entries
        .last()
        .map(|entry| entry.sequence)
        .ok_or_else(|| {
            SpoolError::Corrupt("watchdog spool export selected no records".to_owned())
        })?;
    let created_at_ms = current_unix_ms()?;
    let expires_at_ms = created_at_ms
        .checked_add(EXPORT_BATCH_TTL_MS)
        .ok_or_else(|| {
            SpoolError::Corrupt("watchdog spool export acknowledgement window overflows".to_owned())
        })?;
    Ok((
        WatchdogSpoolExportBatch {
            schema_version: SPOOL_EXPORT_CURSOR_SCHEMA_VERSION,
            batch_id: export_batch_identity(
                predecessor,
                first_sequence,
                last_sequence,
                high_water,
                &record_digests,
                "watchdog-spool-batch-id-v1",
            ),
            installation_id: predecessor.installation_id.clone(),
            watchdog_generation: predecessor.watchdog_generation,
            watchdog_epoch: predecessor.watchdog_epoch,
            predecessor_cursor: predecessor.clone(),
            first_sequence,
            last_sequence,
            high_water_sequence: high_water,
            item_count: export_entries.len(),
            byte_size,
            batch_digest: export_batch_identity(
                predecessor,
                first_sequence,
                last_sequence,
                high_water,
                &record_digests,
                "watchdog-spool-batch-digest-v1",
            ),
            is_empty_batch: false,
            created_at_ms,
            expires_at_ms,
            entries: export_entries,
        },
        raws,
    ))
}

/// Builds the explicit empty batch for `acknowledged == high-water`.
///
/// The empty shape carries no entries, zero counts, and
/// `first == last + 1 == high-water + 1`; its identity still binds the owner
/// identities and endpoints so a mismatched acknowledgement cannot reuse it.
fn build_empty_export_batch(
    predecessor: &WatchdogSpoolCursor,
    high_water: u64,
) -> Result<WatchdogSpoolExportBatch, SpoolError> {
    let first_sequence = high_water
        .checked_add(1)
        .ok_or(WatchdogSpoolReconciliationError::PredecessorMismatch)?;
    let created_at_ms = current_unix_ms()?;
    let expires_at_ms = created_at_ms
        .checked_add(EXPORT_BATCH_TTL_MS)
        .ok_or_else(|| {
            SpoolError::Corrupt("watchdog spool export acknowledgement window overflows".to_owned())
        })?;
    Ok(WatchdogSpoolExportBatch {
        schema_version: SPOOL_EXPORT_CURSOR_SCHEMA_VERSION,
        batch_id: export_batch_identity(
            predecessor,
            first_sequence,
            high_water,
            high_water,
            &[],
            "watchdog-spool-batch-id-v1",
        ),
        installation_id: predecessor.installation_id.clone(),
        watchdog_generation: predecessor.watchdog_generation,
        watchdog_epoch: predecessor.watchdog_epoch,
        predecessor_cursor: predecessor.clone(),
        first_sequence,
        last_sequence: high_water,
        high_water_sequence: high_water,
        entries: Vec::new(),
        item_count: 0,
        byte_size: 0,
        batch_digest: export_batch_identity(
            predecessor,
            first_sequence,
            high_water,
            high_water,
            &[],
            "watchdog-spool-batch-digest-v1",
        ),
        is_empty_batch: true,
        created_at_ms,
        expires_at_ms,
    })
}

/// Plans the compaction prefix below the acknowledged cursor.
///
/// Candidates are retained entries at or below the acknowledged sequence,
/// except a `Gap` or `Recovery` boundary entry at or above the cursor, which
/// is retained until a later acknowledgement advances past it. Removal also
/// stops below the first unresolved `Gap` or `Recovery` marker above the
/// cursor; that bound is implied by the candidate ceiling and enforced here
/// explicitly so compaction can never cross an unresolved gap. A spool-local
/// intent is never a compaction candidate at any sequence: the original
/// Watchdog record must stay retained so the fenced Kernel record and the
/// Governor's later decision stay forensically linked to it, and retention
/// pressure eviction is the only thing that may ever drop it.
fn compaction_plan(entries: &[WatchdogSpoolEntry], acknowledged: u64) -> Vec<u64> {
    let first_unresolved = entries
        .iter()
        .filter(|entry| {
            !matches!(
                export_payload_kind(&entry.payload),
                WatchdogSpoolPayloadKind::Heartbeat
            ) && entry.sequence > acknowledged
        })
        .map(|entry| entry.sequence)
        .min();
    entries
        .iter()
        .filter(|entry| entry.sequence <= acknowledged)
        .filter(|entry| !intent::is_intent_payload(&entry.payload))
        .filter(|entry| {
            matches!(
                export_payload_kind(&entry.payload),
                WatchdogSpoolPayloadKind::Heartbeat
            ) || entry.sequence < acknowledged
        })
        .filter(|entry| first_unresolved.is_none_or(|marker| entry.sequence < marker))
        .map(|entry| entry.sequence)
        .collect()
}
