//! Physical protected spool cell for the independent Runtime 0.17 watchdog.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01, ARCH-WDG-02.
//! Implementation: I8.1, I8.3, I8.10, I8.13, I2.23.
//! Physical protected spool only — no semantic/canonical/Kernel/Governor
//! authority and no new default or retry; bytes/layout/recovery/high-water/fail-closed
//! behavior is preserved verbatim from the reviewed production cell.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use eliot_contracts::sha256_hex;
use eliot_platform_windows::{ProtectedRuntimePathLease, windows_paths_equal};
use eliot_watchdog_core::{
    WatchdogSpoolAcknowledgement, WatchdogSpoolCursor, WatchdogSpoolExportBatch,
    WatchdogSpoolExportEntry, WatchdogSpoolPayloadKind, WatchdogSpoolReconciliationError,
    acknowledgement_advances_cursor, is_duplicate_ack, validate_acknowledgement, validate_batch,
    validate_batch_freshness, validate_cursor,
};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};

use crate::health_projection::{WatchdogHealthCorpus, encode_identity};
use crate::{
    AdmittedIsolatedDestination, SERVICE_NAME, SpoolError, WatchdogRuntimeBinding, current_unix_ms,
};

/// Spool-local Host responsiveness/recovery attempt and pre-authorized
/// containment request records (I8.3). They are spool-local restricted
/// non-semantic records like the intents below, they travel inside their export
/// window under the existing `Recovery` class, and compaction never removes
/// them, so the retained attempt and the request this Watchdog emitted stay
/// readable for later canonical reconciliation.
pub(crate) mod attempt;
pub(crate) mod backup;
mod codec;
/// Durable failure-episode deduplication and recurrence state (I8.3, I8.9).
///
/// The episode key and the source-event admission decision are derived in the
/// owner-neutral core; this module owns their durable form and the bounded
/// histories, and it is written inside the caller's existing spool transaction
/// together with the record one accepted revision produced. It is a table in
/// this owner's own `watchdog.redb`, not a second store, a second database, or
/// an in-memory set, and it is not a compaction candidate, so an unresolved
/// episode is never dropped.
pub(crate) mod episode;
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
    collect_entries, decode_entry, decode_header, decode_high_water, encode_header,
    read_high_water, validate_header_stream, validate_high_water, validate_high_water_last,
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
/// Single-key row of the latest shared I8.2 coverage manifest (#1755 W6).
///
/// The supervision tick retains the newest published
/// `ObservationCoverageManifest` here, replacing the previous row, so the
/// payload the wrapper builds reaches durable owner evidence instead of only
/// a debug-log summary. One row only: history is bounded by replacement, and
/// the manifest carries its own interval window, so a reader always sees
/// which interval the retained manifest covers. Separate from the entries,
/// high-water, cursor, and receipt tables: backup captures, export batches,
/// and the retained-record denominator never read this table.
pub(crate) const SPOOL_COVERAGE_MANIFEST_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eliot_watchdog_coverage_manifest_v1");
pub(crate) const SPOOL_JOURNAL_CURSOR_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_watchdog_journal_cursor_v1");
/// Single-key row of the latest shared coverage manifest.
pub(crate) const SPOOL_COVERAGE_MANIFEST_KEY: u64 = 0;
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

    /// Opens the spool of one EXTERNALLY ADMITTED isolated destination
    /// installation.
    ///
    /// This is the destination-side counterpart of
    /// [`Self::open_runtime_binding`]: the same protected path lease, the same
    /// path-identity verification, and the same initialization/recovery path,
    /// reached through the destination's own admitted binding instead of this
    /// owner's. It is the only way an isolated restore import reaches a
    /// destination database, which is what makes "the import targets the
    /// admitted destination" structural rather than a matter of a validated
    /// string.
    ///
    /// The destination is a NEW isolated installation, so its spool is normally
    /// absent; opening it creates and initializes a fresh, empty destination
    /// spool through the same retained no-follow lease and identity proof as
    /// the owner's own. No destination lease, heartbeat, supervision
    /// authority, or epoch is touched, read, or required.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the destination's spool path is not the
    /// canonical protected path, its retained file identity cannot be proved,
    /// its database cannot be opened, or its header fails initialization or
    /// recovery.
    pub(crate) fn open_isolated_destination(
        destination: &AdmittedIsolatedDestination,
    ) -> Result<Self, SpoolError> {
        let _span = tracing::debug_span!("watchdog.destination_spool_open").entered();
        tracing::debug!(
            event = "watchdog.destination_spool_open_attempted",
            observation = "attempted",
            "opening the admitted isolated destination spool without payload material"
        );
        let path = watchdog_spool_path(destination.watchdog_state_root());
        let path_lease = ProtectedRuntimePathLease::open_or_create_absolute(&path)
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        if path_lease.path() != path {
            return Err(SpoolError::InvalidProtectedRoot);
        }
        path_lease
            .verify_path_identity()
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        // A new isolated installation has no spool yet: the retained lease
        // above materializes an empty file, which `open` would refuse as
        // invalid data. `create` initializes a missing-or-empty file and
        // opens an existing valid database without truncating it, so a
        // first import starts a fresh spool while a replayed import
        // reopens the retained one. (Issue #955: without this, no fresh
        // destination could ever import.)
        let database = Database::create(path_lease.path())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let spool = Self {
            database,
            _path_lease: Some(path_lease),
        };
        spool.initialize_or_recover()?;
        Ok(spool)
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
    /// delegates fence construction to
    /// [`backup::capture_fence_with_channel_coverage`]. `channel_coverage` is
    /// the owner-bound I8.2 report to carry beside the fence's retained-record
    /// denominator; it is validated inside that builder and never conjoined with
    /// the denominator by this owner. The result is an immutable data handle
    /// carrying digests and redacted receipts only: no live redb file is opened
    /// or copied, and no lease, heartbeat, supervision authority, epoch,
    /// restart, deletion, or cutover state is touched.
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
    /// is missing or invalid, any retained entry is expired, missing,
    /// duplicated, conflicting, or malformed, or a supplied channel-coverage
    /// report is not consistent with the sensor map and its own observed
    /// classes.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "955 owner-method contract takes the capture bindings by value; the fence builder borrows them"
    )]
    pub fn snapshot_backup(
        &self,
        params: backup::CaptureFenceParams,
        limits: WatchdogSpoolBackupLimits,
        channel_coverage: Option<&crate::observation_coverage::IntervalCoverageReport>,
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
        backup::capture_fence_with_channel_coverage(
            &header,
            &entries,
            high_water,
            &params,
            channel_coverage,
        )
    }

    /// Imports an isolated-restore step chain as quarantined historical evidence
    /// INTO THE EXTERNALLY ADMITTED ISOLATED DESTINATION INSTALLATION.
    ///
    /// The destination is `destination: Option<&AdmittedIsolatedDestination>`,
    /// and that is the whole point of the signature: an import has exactly one
    /// admissible target, and it is the destination installation whose registry,
    /// approved generation, artifact digests, and retained runtime roots were
    /// proved by [`crate::admit_isolated_destination`] before this call. When no
    /// destination is admitted there is nothing this owner may write to, and the
    /// import REFUSES — it never falls back to the currently active
    /// installation's spool. The refusal names the absent admission.
    ///
    /// It is an associated function rather than a method on `&self`, and
    /// deliberately so. An import is not an operation on the importing owner's
    /// own spool, and withholding `self` keeps the active installation's
    /// database out of scope entirely: the destination spool is opened here
    /// from the admitted binding alone.
    ///
    /// The active installation is `active: &WatchdogRuntimeBinding`, NOT a
    /// caller string, and that is the second half of the signature. The
    /// ACTIVE side of the isolation check is read out of the owner's own
    /// retained admission — the digest-verified, root-leased binding the live
    /// spool itself was opened from — never from the request. A caller can
    /// therefore not present a convenient "active" identity and make the
    /// comparison a tautology: the only active installation this owner knows
    /// is the one whose approved manifest and retained root leases it holds.
    /// This is the same owner-issued fact the backup port is constructed from.
    ///
    /// Isolation is proved on BOTH owner-issued axes, not one:
    ///
    /// - identity: the destination's OWNER-ISSUED installation identity
    ///   ([`AdmittedIsolatedDestination::installation`], read from the
    ///   destination's own registry-selected approved manifest) must differ
    ///   from the source and from the active installation's OWNER-ISSUED
    ///   identity (the active binding's own selected manifest), through
    ///   [`backup::validate_isolated_destination`]; and
    /// - storage: the destination's OWNER-ISSUED Watchdog state root must not be
    ///   the active installation's OWNER-ISSUED state root, compared with the
    ///   same `windows_paths_equal` owner the admission uses.
    ///
    /// The second comparison is strictly stronger than the first and is the
    /// one that makes "an import never targets the active installation"
    /// structural: two distinct installation identities that nevertheless
    /// resolve to ONE state root would satisfy the identity check alone, and
    /// would make the import write into the live installation's own
    /// `watchdog.redb`. That is refused here.
    ///
    /// The chain is gated through [`backup::validate_restore_chain`], rooted at
    /// the admitted preparation digest carried as the first step's predecessor.
    /// The destination's own spool is opened once through
    /// [`Self::open_isolated_destination`], and every retained-evidence read and
    /// every accepted append goes through THAT spool. Each accepted step is
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
    /// The idempotency evidence is read from the DESTINATION's own retained
    /// records, not from this owner's: repeated import is a statement about
    /// what the destination already holds.
    ///
    /// The returned disposition never reports a known-zero over an unresolved
    /// signal. If the destination already retains a coverage-invalidating
    /// record that is not this operation's own quarantine — a `Gap`, an
    /// unreconciled problem/incident intent, or a `Recovery` from another
    /// source — classified through the same [`backup::SpoolFenceEntryKind`]
    /// owner the capture path uses, the disposition is
    /// [`backup::SpoolRestoreDisposition::Unknown`] even when every presented
    /// step was applied or was a duplicate. `Unknown` is what
    /// `backup::acceptance_allowed` refuses, so recovery acceptance stays
    /// blocked while a critical signal is unresolved instead of defaulting to
    /// zero. Those records are never dropped, reordered, or downgraded to make
    /// the import look clean, and this operation's own historical evidence is
    /// excluded from the test so a repeated import still observes its own
    /// disposition.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::InvalidLease`] when no externally admitted
    /// destination installation binding was supplied — the absent admission is
    /// refused, never substituted. Returns [`SpoolError`] when the destination
    /// is not isolated from the source and active installations on either the
    /// owner-issued identity axis or the owner-issued state-root axis, its spool
    /// cannot be opened, the step chain is empty, malformed, non-consecutive, or
    /// unlinked, the bounded step count is exceeded, or any step conflicts with
    /// already quarantined evidence.
    pub fn import_backup_isolated(
        source_installation: &str,
        destination: Option<&AdmittedIsolatedDestination>,
        active: &WatchdogRuntimeBinding,
        steps: &[backup::SpoolRestoreStep],
    ) -> Result<backup::SpoolRestoreDisposition, SpoolError> {
        let Some(destination) = destination else {
            return Err(SpoolError::InvalidLease(
                "watchdog spool backup import refuses to run: no externally admitted isolated destination installation binding was supplied, and an import targets only that admitted destination".to_owned(),
            ));
        };
        let active_installation = owner_issued_active_installation(active);
        backup::validate_isolated_destination(
            source_installation,
            destination.installation(),
            active_installation,
        )?;
        // The identity axis above does not by itself prove a different store;
        // the second, independent owner-issued axis is the Watchdog state root,
        // refused by `reject_shared_active_state_root`.
        reject_shared_active_state_root(destination, active)?;
        validate_import_step_budget(steps)?;
        let prepare_digest = steps
            .first()
            .map_or("", |step| step.predecessor_digest.as_str());
        backup::validate_restore_chain(prepare_digest, steps)?;
        // Every read below and every append inside the loop are against the
        // admitted destination installation's own spool. The importing owner's
        // own spool is not even reachable from here: there is no `self`.
        let destination_spool = WatchdogSpool::open_isolated_destination(destination)?;
        let retained = destination_spool.readback()?;
        // Unreconciled critical signal/intent identities already retained by the
        // destination installation, read by `has_unresolved_critical` through the
        // same single owner (`SpoolFenceEntryKind`) the capture path uses.
        let unresolved_critical = has_unresolved_critical(&retained);
        // The destination's own previously written quarantine records, replayed
        // against the presented steps below so a repeated import still observes
        // its own `Duplicate` disposition.
        let mut quarantined = retained_import_quarantine(&retained);
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
            destination_spool.append(
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
        // An unreconciled critical signal/intent already retained by the
        // destination means its historical coverage is NOT closed. Reporting
        // `Accepted` or `Duplicate` there would be the known-zero default this
        // path must never produce: it would let recovery acceptance proceed
        // over an unresolved signal. `Unknown` is the honest disposition and
        // `acceptance_allowed` fails closed on it, keeping the signal visible
        // until it is actually reconciled. The records themselves are never
        // dropped, reordered, or downgraded. Steps already appended stay
        // appended: this narrows the reported disposition, it never undoes an
        // accepted, bounded, quarantined append.
        if unresolved_critical {
            disposition = backup::SpoolRestoreDisposition::Unknown;
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

    /// Journals one Host responsiveness/recovery attempt record (I8.3).
    ///
    /// This is the ordinary append path through the owner transaction, so the
    /// retained attempt and the record every later canonical reconciliation reads
    /// are the same bytes. The record is observation material only: it states
    /// what this bounded attempt did and did not establish, never health, never
    /// restart eligibility, and never a canonical Problem or Incident.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the record is not canonical or the retained
    /// spool, header, or high-water fails validation.
    pub(crate) fn journal_host_attempt(
        &self,
        observed_at_ms: u64,
        record: &attempt::HostAttemptRecord,
    ) -> Result<WatchdogSpoolEntry, SpoolError> {
        let (outcome, entry) = self.append_with_entry(observed_at_ms, record.to_payload())?;
        let _ = outcome;
        Ok(entry)
    }
    /// Journals one pre-authorized containment request record (I8.3).
    ///
    /// The caller reaches this only after the boundary fence admitted the
    /// request, so the retained copy names a request this Watchdog was
    /// authorized to emit. It records the request, never an executed effect.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the record is not canonical or the retained
    /// spool, header, or high-water fails validation.
    pub(crate) fn journal_containment_request(
        &self,
        observed_at_ms: u64,
        record: &attempt::ContainmentRequestRecord,
    ) -> Result<WatchdogSpoolEntry, SpoolError> {
        let (outcome, entry) = self.append_with_entry(observed_at_ms, record.to_payload())?;
        let _ = outcome;
        Ok(entry)
    }

    /// Appends one payload and returns both the retention outcome and the exact
    /// entry the append created.
    ///
    /// Under retention pressure [`WatchdogSpool::append_in_transaction`] writes
    /// an extra pressure `Gap` marker before the payload, so reading the
    /// high-water mark afterwards would not name the record this call created.
    fn append_with_entry(
        &self,
        observed_at_ms: u64,
        payload: WatchdogSpoolPayload,
    ) -> Result<(SpoolAppendOutcome, WatchdogSpoolEntry), SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let (outcome, entry) = Self::append_in_transaction(&write, observed_at_ms, payload)?;
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        Ok((outcome, entry))
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

    /// Retains the newest published shared I8.2 coverage manifest (#1755 W6).
    ///
    /// The manifest is validated before anything is written, so an invalid
    /// manifest is refused whole and the previously retained row stands
    /// untouched. On success the single manifest row is replaced: this is the
    /// delivery of the wrapper-built payload into durable owner evidence. An
    /// omitted interval retains nothing and clears nothing; the reader sees
    /// the last published manifest with its own interval window.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the manifest does not validate, cannot be
    /// serialized, or the row cannot be committed.
    pub(crate) fn retain_shared_coverage_manifest(
        &self,
        manifest: &eliot_evaluation_contracts::ObservationCoverageManifest,
    ) -> Result<(), SpoolError> {
        manifest.validate().map_err(|error| {
            SpoolError::Corrupt(format!(
                "refused to retain an invalid coverage manifest: {error:?}"
            ))
        })?;
        let bytes = serde_json::to_vec(manifest)
            .map_err(|error| SpoolError::Serialization(error.to_string()))?;
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        {
            let mut table = write
                .open_table(SPOOL_COVERAGE_MANIFEST_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            table
                .insert(SPOOL_COVERAGE_MANIFEST_KEY, bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
        }
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        Ok(())
    }

    /// Reads the latest retained shared I8.2 coverage manifest (#1755 W6).
    ///
    /// Test-only readback for the retain proof: no production path consumes
    /// the retained row yet, so the reader serves the verification suite
    /// rather than shipping a caller-less production API.
    ///
    /// `Ok(None)` when no interval has retained one yet. A stored row that no
    /// longer parses or validates is refused as corrupt rather than served as
    /// evidence: fail closed, never a best-effort manifest.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the database cannot be read or the stored
    /// row is corrupt.
    #[cfg(test)]
    pub(crate) fn read_shared_coverage_manifest(
        &self,
    ) -> Result<Option<eliot_evaluation_contracts::ObservationCoverageManifest>, SpoolError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let table = match read.open_table(SPOOL_COVERAGE_MANIFEST_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        };
        let row = table
            .get(SPOOL_COVERAGE_MANIFEST_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let manifest: eliot_evaluation_contracts::ObservationCoverageManifest =
            serde_json::from_slice(row.value()).map_err(|error| {
                SpoolError::Corrupt(format!(
                    "stored coverage manifest is not valid JSON: {error}"
                ))
            })?;
        manifest.validate().map_err(|error| {
            SpoolError::Corrupt(format!(
                "stored coverage manifest does not validate: {error:?}"
            ))
        })?;
        Ok(Some(manifest))
    }

    /// Retains the journal read position for one volume (#1755 W3).
    ///
    /// The cursor is validated before anything is written: an unusable
    /// volume label or a zero journal identity is refused whole and the
    /// previously retained row stands untouched. On success the volume's
    /// row is replaced: the cursor always names the last consumed USN of
    /// the journal lifetime the adapter stands behind. A missing journal
    /// writes no cursor — absence of a position is not a position.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the volume label or cursor is unusable,
    /// cannot be serialized, or the row cannot be committed.
    pub(crate) fn retain_journal_cursor(
        &self,
        volume: &str,
        cursor: &eliot_platform_windows::UsnCursor,
    ) -> Result<(), SpoolError> {
        validate_journal_cursor_volume(volume)?;
        if cursor.journal_id == 0 {
            return Err(SpoolError::Corrupt(
                "refused to retain a journal cursor with no journal identity".to_owned(),
            ));
        }
        let record = StoredJournalCursorRecord {
            schema_version: JOURNAL_CURSOR_SCHEMA_VERSION,
            journal_id: cursor.journal_id,
            next_usn: cursor.next_usn,
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|error| SpoolError::Serialization(error.to_string()))?;
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        {
            let mut table = write
                .open_table(SPOOL_JOURNAL_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            table
                .insert(volume, bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
        }
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        Ok(())
    }

    /// Reads the retained journal read position for one volume (#1755 W3).
    ///
    /// `Ok(None)` when no page was ever retained for the volume. A stored
    /// row that no longer parses, names another schema, or carries no
    /// journal identity is refused as corrupt rather than served as a
    /// position: resuming from a forged or decayed cursor would replay the
    /// wrong history as continuity.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the database cannot be read or the
    /// stored row is corrupt.
    pub(crate) fn read_journal_cursor(
        &self,
        volume: &str,
    ) -> Result<Option<eliot_platform_windows::UsnCursor>, SpoolError> {
        validate_journal_cursor_volume(volume)?;
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let table = match read.open_table(SPOOL_JOURNAL_CURSOR_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        };
        let row = table
            .get(volume)
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let record: StoredJournalCursorRecord =
            serde_json::from_slice(row.value()).map_err(|error| {
                SpoolError::Corrupt(format!("stored journal cursor is not valid JSON: {error}"))
            })?;
        decode_journal_cursor_record(&record)
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
    /// `admission_ordinal` is the ordinal half of the owner-issued admission
    /// sequence, and the generation half is the lineage's own. The owner issues
    /// that sequence before it calls this, so the order the rule enforces is the
    /// order of the owner's own admission events and not the order in which
    /// write transactions happened to commit. An observation that is not
    /// strictly after the episode's latest accepted one is refused whole, so it
    /// can never move the episode's position backward; the wall-clock reading it
    /// also carries is retained as diagnostic evidence only.
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
        admission_ordinal: u64,
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
            admission_ordinal,
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
    /// `admission_ordinal` is the ordinal half of the owner-issued admission
    /// sequence the owner issued for this recovery, and it is what orders the
    /// recovery against the episode's latest accepted observation.
    ///
    /// Recovery is serialized against observations under the same writer
    /// discipline: the episode and its revision are re-read and re-validated
    /// inside one write transaction, and a recovery whose owner-issued sequence
    /// is not strictly after the episode's latest accepted one is refused, so a
    /// later recovery can neither silently overwrite a concurrently accepted
    /// newer observation — including one observed in the same millisecond, which
    /// no timestamp comparison can separate — nor report a refusal as a closure.
    ///
    /// Closing withdraws nothing. It claims no canonical resolution: the
    /// episode's spooled intents stay retained and unacknowledged until the
    /// fenced Kernel route reconciles them, and it never touches their records,
    /// their submit-once receipts, or the spool itself.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the rule state is not canonical, the recovery
    /// identity is uninitialized, carries no owner-issued admission sequence, or
    /// the state cannot be written.
    pub(crate) fn observe_governor_recovery(
        &self,
        presenting_generation: u64,
        admission_ordinal: u64,
        observed_at_ms: u64,
    ) -> Result<bool, SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let mut state = Self::read_intent_rule_state_in(&write)?;
        let closed_episode_id =
            match state.close_episode(presenting_generation, admission_ordinal, observed_at_ms)? {
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
    ///
    /// The Watchdog owner also reads it once at construction, to re-seed its own
    /// admission sequence above the position its durable episode row already
    /// records, so a restarted owner never replays an ordinal it already issued.
    pub(crate) fn read_intent_rule_state(
        &self,
    ) -> Result<intent::GovernorIntentRuleState, SpoolError> {
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

    /// Resolves one observed failure against its durable failure episode and
    /// persists the deduplication state in the same owner transaction as the
    /// record one accepted revision produced.
    ///
    /// The episode key is derived in the owner-neutral core from the
    /// observation's own rule revision, scope, subject, generation and
    /// discriminating failure class. The source event identity is **not** part
    /// of that key: it is compared against the episode's separate, bounded
    /// accepted-event index, which is what makes a retransmission inert.
    ///
    /// Three outcomes, and no fourth:
    ///
    /// * **New evidence.** The exact `(event id, payload digest)` pair has not
    ///   been accepted by this episode. Exactly one `Gap` record — the same
    ///   retained record the ordinary gap path already appends — is appended
    ///   through [`Self::append_in_transaction`], never through a nested write,
    ///   and the episode's accepted revision, occurrence count, evidence time,
    ///   accepted-event index and the exact record reference (sequence plus
    ///   record digest, bound the way an export batch binds it) all commit with
    ///   the spool's own high-water update in one transaction. A failure before
    ///   that commit leaves neither a record nor an advanced episode.
    /// * **Retransmission.** The same identity was already accepted with the
    ///   same digest. Nothing is written, no record is appended, the occurrence
    ///   count and the evidence time are reported unchanged, and the caller is
    ///   handed the revision and record this episode already accepted. A
    ///   restart, a duplicate tick, or a lost acknowledgement therefore reuses
    ///   the accepted revision instead of emitting a fresh alert.
    /// * **Refused.** The same identity with a *different* digest is a typed
    ///   conflict, and a bounded history that cannot grow without either
    ///   dropping an already-accepted identity or erasing an unresolved
    ///   episode's reopen history is refused rather than trimmed. Neither writes
    ///   anything, and neither opens a second episode.
    ///
    /// When the commit outcome is uncertain, the call reconciles the offered
    /// observation by its own identity before deciding: if that event is now
    /// accepted it reports the accepted revision, otherwise it reports the
    /// failure. Neither branch can mint a second record for one source event.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the episode identity is unusable, the stored
    /// row is not canonical, a bound is already reached, the record cannot be
    /// encoded, or the spool cannot be read or written.
    pub(crate) fn observe_signal_episode(
        &self,
        observation: episode::SignalEpisodeObservation,
    ) -> Result<episode::SignalEpisodeOutcome, SpoolError> {
        // The observation is owned exactly once and decomposed here, so each
        // owner-supplied fact below is read from the value this function
        // received rather than from a borrow of a caller's copy. The source
        // event is taken over by value: it is the identity this function
        // classifies against and later reconciles against, and keeping one
        // owner of it means the reconciliation can never name a second event.
        let episode::SignalEpisodeObservation {
            identity,
            source_event,
            reopen_condition,
            observed_at_ms,
            producer_generation,
            record_reason,
        } = observation;
        let episode_key =
            eliot_watchdog_core::FailureEpisodeKey::derive(&identity).map_err(|error| {
                SpoolError::Corrupt(format!(
                    "watchdog signal episode identity is not derivable: {error:?}"
                ))
            })?;
        let ledger_key = episode::episode_ledger_key(episode_key.as_str());
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        // The episode table is opened through the write transaction's own
        // inherent `open_table`, which creates it when absent, and the read
        // guard is released before anything else opens it for writing.
        let state = {
            let table = write
                .open_table(episode::SIGNAL_EPISODE_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            if let Some(state) = episode::read_episode(&table, ledger_key.as_str())? {
                state
            } else {
                // A new episode takes one table slot, and the table is
                // bounded. The check is against the real retained row count
                // rather than a caller's number, so an over-full table
                // refuses the new episode instead of the closer later walking
                // past it.
                let stored = episode::stored_episode_keys(&table)?.len();
                if stored >= episode::MAX_SIGNAL_EPISODES {
                    return Err(SpoolError::Corrupt(
                        "watchdog signal episode table is at its bound; refusing to open another episode rather than dropping an existing one"
                            .to_owned(),
                    ));
                }
                episode::StoredSignalEpisode::fresh(&identity, &episode_key, &reopen_condition)
            }
        };
        let admission = state.classify(&source_event)?;
        let (outcome, emission) = Self::resolve_signal_episode_admission(
            &write,
            state,
            &admission,
            &source_event,
            observed_at_ms,
            producer_generation,
            record_reason,
        )?;
        let Some(state) = emission else {
            // Retransmission and refusal wrote nothing; dropping the
            // uncommitted transaction is the durable outcome, and reporting it
            // is not a lost record.
            drop(write);
            return Ok(outcome);
        };
        episode::write_episode(&write, ledger_key.as_str(), &state)?;
        match write.commit() {
            Ok(()) => Ok(outcome),
            Err(error) => {
                // The commit outcome is uncertain. Reconcile this exact source
                // event by its own identity before deciding, so the caller is
                // never handed a second record for an event that already has
                // one.
                match self.reconcile_accepted_signal_event(ledger_key.as_str(), &source_event) {
                    Some(reconciled) => Ok(reconciled),
                    None => Err(SpoolError::Database(error.to_string())),
                }
            }
        }
    }

    /// Reconciles the revision an episode already accepted for exactly this
    /// source event identity and digest.
    ///
    /// Read-only, and reached only after an uncertain commit of the one arm
    /// that writes — a genuinely new source event. It reports the accepted
    /// revision when this exact event is now part of the episode, and `None`
    /// otherwise, which is the honest answer: the caller is then told the
    /// attempt failed rather than handed a revision that was never committed.
    fn reconcile_accepted_signal_event(
        &self,
        ledger_key: &str,
        source_event: &eliot_watchdog_core::AcceptedSourceEvent,
    ) -> Option<episode::SignalEpisodeOutcome> {
        let read = self.database.begin_read().ok()?;
        // A read transaction's `open_table` is the other half of the same
        // inherent pair, and unlike the write path it does not create the table:
        // a spool that never opened an episode simply has nothing to reconcile.
        let table = read.open_table(episode::SIGNAL_EPISODE_TABLE).ok()?;
        let state = episode::read_episode(&table, ledger_key).ok()??;
        if state.classify(source_event).ok()?.is_new_evidence() {
            return None;
        }
        let (revision, record) = state.accepted().ok()?;
        let progress = state.progress();
        Some(episode::SignalEpisodeOutcome::Reused {
            revision,
            independent_occurrences: progress.independent_occurrences,
            evidence_observed_at_ms: progress.evidence_observed_at_ms,
            record,
        })
    }

    /// Turns one already-classified admission into the outcome its caller can
    /// commit, inside the write transaction the caller already holds.
    ///
    /// This opens, closes and commits no transaction of its own: the one
    /// `redb` write transaction its caller opened stays open across this call,
    /// which is what keeps the appended record, the advanced episode row and
    /// the spool's own high-water update one durability point. The append is
    /// still [`Self::append_in_transaction`] on the caller's transaction and
    /// still happens before the episode row naming that record is accepted, so
    /// no side effect moves relative to a `?` or to the caller's `commit()`.
    ///
    /// The returned pair carries the advanced row when this admission wrote
    /// something and `None` when it wrote nothing. A retransmission and a
    /// refusal advance no occurrence count, no evidence time and no accepted
    /// revision, so handing their caller a row to write would offer exactly the
    /// write the deduplication guarantee forbids: the caller drops its
    /// uncommitted transaction instead.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the episode is at a bound, the record cannot
    /// be encoded, or the append inside the caller's transaction fails. The
    /// caller's transaction is then dropped uncommitted, exactly as it would be
    /// had this step failed in place.
    fn resolve_signal_episode_admission(
        write: &WriteTransaction,
        mut state: episode::StoredSignalEpisode,
        admission: &eliot_watchdog_core::SourceEventAdmission,
        source_event: &eliot_watchdog_core::AcceptedSourceEvent,
        observed_at_ms: u64,
        producer_generation: u64,
        record_reason: crate::GapRecoveryReason,
    ) -> Result<
        (
            episode::SignalEpisodeOutcome,
            Option<episode::StoredSignalEpisode>,
        ),
        SpoolError,
    > {
        match admission {
            eliot_watchdog_core::SourceEventAdmission::Retransmission { .. } => {
                // Already accepted under the same identity and digest: reuse
                // the accepted revision and write nothing, so the caller's
                // uncommitted transaction is dropped without a write.
                let (revision, record) = state.accepted()?;
                let progress = state.progress();
                Ok((
                    episode::SignalEpisodeOutcome::Reused {
                        revision,
                        independent_occurrences: progress.independent_occurrences,
                        evidence_observed_at_ms: progress.evidence_observed_at_ms,
                        record,
                    },
                    None,
                ))
            }
            eliot_watchdog_core::SourceEventAdmission::ConflictingPayload {
                recorded_payload_digest,
            } => Ok((
                episode::SignalEpisodeOutcome::Refused(
                    episode::SignalEpisodeRefusal::ConflictingSourceEventPayload {
                        event_id: source_event.event_id.clone(),
                        recorded_payload_digest: recorded_payload_digest.clone(),
                    },
                ),
                None,
            )),
            eliot_watchdog_core::SourceEventAdmission::NewEvidence { .. } => {
                if let Some(refusal) = state.bound_refusal(admission) {
                    Ok((episode::SignalEpisodeOutcome::Refused(refusal), None))
                } else {
                    let payload = WatchdogSpoolPayload::Gap {
                        service: SERVICE_NAME.to_owned(),
                        reason: record_reason,
                        coverage_claimed: false,
                    };
                    let (_appended, created) =
                        Self::append_in_transaction(write, observed_at_ms, payload)?;
                    // The identity of the record this transaction just created,
                    // bound the way an export batch binds it. A
                    // retention-pressure gap record written ahead of it can
                    // never be mistaken for this observation, and an interleaved
                    // append can never substitute another entry's sequence.
                    let raw = encode_entry(&created)?;
                    let (_payload_digest, record_digest) = export_record_digests(&created, &raw);
                    let record = episode::StoredSignalRecordRef {
                        sequence: created.sequence,
                        record_digest,
                        observed_at_ms: created.observed_at_ms,
                    };
                    let reopened = state.accept(
                        source_event,
                        observed_at_ms,
                        producer_generation,
                        admission,
                        record.clone(),
                    )?;
                    let progress = state.progress();
                    Ok((
                        episode::SignalEpisodeOutcome::Accepted {
                            revision: progress.revision,
                            independent_occurrences: progress.independent_occurrences,
                            record,
                            reopened,
                        },
                        Some(state),
                    ))
                }
            }
        }
    }

    /// Closes every open failure episode after a live admission, retaining each
    /// episode's accepted events, revision, record reference and reopen history.
    ///
    /// A live admission is the only closer: no timer, no export acknowledgement
    /// and no caller-chosen reason reaches this. Closing withdraws nothing, so a
    /// later recurrence is recognised against the episode it recurs from and
    /// appends a reopen record rather than starting an unrelated first
    /// observation.
    ///
    /// Every open episode is closed, not a bounded prefix of them. The bound is
    /// the table's own cap: a new episode is refused at
    /// [`episode::MAX_SIGNAL_EPISODES`] rather than displacing an existing one,
    /// so the set of open episodes can never exceed what one pass over the table
    /// can close. That is what makes this closer complete rather than a partial
    /// pass that silently leaves an episode open. An episode that is already
    /// closed is not rewritten, and a failure before the commit leaves every
    /// episode exactly as it was.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when a stored row is not canonical, the table
    /// holds more episodes than its own cap, or the state cannot be written.
    pub(crate) fn close_signal_episodes(&self) -> Result<u64, SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        // One read pass over the episode table decides which rows actually
        // change, and its read guard is released before the write pass reopens
        // the same table for writing: redb gives a write transaction one guard
        // per open table, and this closer must not hold two at once.
        let to_close = {
            let table = write
                .open_table(episode::SIGNAL_EPISODE_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            let keys = episode::stored_episode_keys(&table)?;
            if keys.len() > episode::MAX_SIGNAL_EPISODES {
                return Err(SpoolError::Corrupt(
                    "watchdog signal episode table exceeds its bound; refusing to close a prefix of it"
                        .to_owned(),
                ));
            }
            let mut to_close = Vec::new();
            for ledger_key in &keys {
                let Some(mut state) = episode::read_episode(&table, ledger_key.as_str())? else {
                    continue;
                };
                if state.close()? {
                    to_close.push((ledger_key.clone(), state));
                }
            }
            to_close
        };
        let mut closed: u64 = 0;
        for (ledger_key, state) in &to_close {
            episode::write_episode(&write, ledger_key.as_str(), state)?;
            closed = closed.saturating_add(1);
        }
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        Ok(closed)
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

    /// Measures this owner's retained observation bank for the I8.18 health
    /// projection.
    ///
    /// One bounded read transaction over the retained records, plus the stored
    /// export cursor and the submit-once receipt ledger this owner already
    /// maintains. Nothing is written, no lease, epoch, or authority is read,
    /// and no record is interpreted beyond the owner's own classification of
    /// what it stored: a record's payload class, its gap reason, its sequence,
    /// its recorded observation time, and the digest of its own encoded bytes.
    ///
    /// The comparison reaches the source rather than the visible final item:
    /// every retained row is decoded through the existing
    /// [`decode_entry`](codec::decode_entry) validator and every row
    /// contributes to the content-digest, acknowledgement, receipt, and
    /// deferred-reason counts, so an old duplicate, a stale record, or a
    /// deferred gap buried anywhere in the retained set is counted rather than
    /// hidden behind a later row.
    ///
    /// Bounded twice. The iteration refuses to exceed the spool's own
    /// [`SPOOL_MAX_RECORDS`] retention ceiling rather than reporting a partial
    /// corpus, and `freshness_window_ms` is the caller's declared owner policy
    /// (this crate's own backup/export window), not a threshold chosen here.
    /// A record is stale only when it is older than that declared window at the
    /// owner clock the caller supplies.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the database cannot be read, the retained
    /// set exceeds the retention ceiling, any retained record fails the
    /// existing decoder, or the stored cursor or receipt ledger is corrupt.
    #[allow(
        clippy::too_many_lines,
        reason = "the bounded corpus measurement keeps its row shape, its single-pass counts, and its evidence digest in one reviewable contour"
    )]
    pub(crate) fn health_corpus_summary(
        &self,
        now_ms: u64,
        freshness_window_ms: u64,
    ) -> Result<WatchdogHealthCorpus, SpoolError> {
        struct RetainedRow {
            sequence: u64,
            observed_at_ms: u64,
            encoded_len: usize,
            content_digest: String,
            payload_class: String,
            gap_reason: Option<String>,
            is_heartbeat: bool,
            is_intent: bool,
        }

        fn payload_class(payload: &WatchdogSpoolPayload) -> String {
            match payload {
                WatchdogSpoolPayload::Heartbeat { .. } => "heartbeat".to_owned(),
                WatchdogSpoolPayload::Gap { .. } => "gap".to_owned(),
                WatchdogSpoolPayload::Recovery { .. } => "recovery".to_owned(),
                WatchdogSpoolPayload::ProblemIntent { .. } => "problem_intent".to_owned(),
                WatchdogSpoolPayload::IncidentIntent { .. } => "incident_intent".to_owned(),
                WatchdogSpoolPayload::HostAttempt { .. } => "host_attempt".to_owned(),
                WatchdogSpoolPayload::ContainmentRequest { .. } => "containment_request".to_owned(),
            }
        }

        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let mut rows: Vec<RetainedRow> = Vec::new();
        match read.open_table(SPOOL_TABLE) {
            Ok(table) => {
                for item in table
                    .iter()
                    .map_err(|error| SpoolError::Database(error.to_string()))?
                {
                    let (key, value) =
                        item.map_err(|error| SpoolError::Database(error.to_string()))?;
                    if key.value() == SPOOL_HEADER_KEY {
                        continue;
                    }
                    if rows.len() as u64 >= SPOOL_MAX_RECORDS {
                        return Err(SpoolError::Corrupt(
                            "watchdog health corpus read exceeds the declared retention ceiling"
                                .to_owned(),
                        ));
                    }
                    // The digest is taken over the ORIGINAL stored bytes and the
                    // bytes are also passed through the existing decoder, so
                    // neither the identity nor the validation is a recomputation
                    // of a value this owner derived some other way.
                    let stored = value.value();
                    let entry = decode_entry(key.value(), stored)?;
                    rows.push(RetainedRow {
                        sequence: key.value(),
                        observed_at_ms: entry.observed_at_ms,
                        encoded_len: stored.len(),
                        content_digest: sha256_hex(stored),
                        payload_class: payload_class(&entry.payload),
                        gap_reason: match &entry.payload {
                            WatchdogSpoolPayload::Gap { reason, .. } => {
                                Some(serde_json::to_string(reason).map_err(|error| {
                                    SpoolError::Serialization(error.to_string())
                                })?)
                            }
                            _ => None,
                        },
                        is_heartbeat: matches!(
                            &entry.payload,
                            WatchdogSpoolPayload::Heartbeat { .. }
                        ),
                        is_intent: intent::is_intent_payload(&entry.payload),
                    });
                }
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {}
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        }
        rows.sort_by_key(|row| row.sequence);
        drop(read);

        let acknowledged_sequence = self.read_export_cursor()?.acknowledged_sequence;
        let receipts: BTreeSet<u64> = self.read_intent_receipt_sequences()?.into_iter().collect();

        let mut retained_records = 0_u64;
        let mut retained_bytes = 0_u64;
        let mut distinct_content = 0_u64;
        let mut content_duplicates = 0_u64;
        let mut reused_acknowledged_content = 0_u64;
        let mut reactivated_after_receipt = 0_u64;
        let mut unacknowledged_records = 0_u64;
        let mut delivered_without_receipt = 0_u64;
        let mut intents_without_receipt = 0_u64;
        let mut stale_records = 0_u64;
        let mut newest_heartbeat_sequence = 0_u64;
        let mut newest_sequence = 0_u64;
        let mut newest_payload_class = String::new();
        let mut last_gap_by_reason: BTreeMap<String, u64> = BTreeMap::new();
        let mut first_sequence_by_digest: BTreeMap<&str, u64> = BTreeMap::new();
        let mut digest_fields: Vec<String> = Vec::new();

        for row in &rows {
            retained_records += 1;
            retained_bytes += row.encoded_len as u64;
            digest_fields.push(row.sequence.to_string());
            digest_fields.push(row.content_digest.clone());
            if now_ms.saturating_sub(row.observed_at_ms) > freshness_window_ms {
                stale_records += 1;
            }
            if row.sequence > acknowledged_sequence {
                unacknowledged_records += 1;
            } else if !receipts.contains(&row.sequence) {
                delivered_without_receipt += 1;
            }
            if row.is_intent && !receipts.contains(&row.sequence) {
                intents_without_receipt += 1;
            }
            if row.is_heartbeat {
                newest_heartbeat_sequence = row.sequence;
            }
            if let Some(reason) = row.gap_reason.as_ref() {
                last_gap_by_reason.insert(reason.clone(), row.sequence);
            }
            if row.sequence >= newest_sequence {
                newest_sequence = row.sequence;
                newest_payload_class.clone_from(&row.payload_class);
            }
            if let Some(first) = first_sequence_by_digest.get(row.content_digest.as_str()) {
                content_duplicates += 1;
                if *first <= acknowledged_sequence {
                    reused_acknowledged_content += 1;
                }
                if receipts.contains(first) {
                    reactivated_after_receipt += 1;
                }
            } else {
                distinct_content += 1;
                first_sequence_by_digest.insert(row.content_digest.as_str(), row.sequence);
            }
        }
        // A gap reason is deferred when no accepted heartbeat was recorded at or
        // after the newest gap carrying it, which is a measured position in the
        // owner's own retained stream and not a judgement about any process.
        let deferred_gap_reasons = last_gap_by_reason
            .values()
            .filter(|sequence| **sequence >= newest_heartbeat_sequence)
            .count() as u64;

        Ok(WatchdogHealthCorpus {
            retained_records,
            retained_bytes,
            distinct_content,
            content_duplicates,
            reused_acknowledged_content,
            reactivated_after_receipt,
            acknowledged_sequence,
            unacknowledged_records,
            delivered_without_receipt,
            intents_without_receipt,
            stale_records,
            deferred_gap_reasons,
            newest_heartbeat_sequence,
            newest_payload_class: newest_payload_class.clone(),
            evidence_id: sha256_hex(
                encode_identity(&[
                    "watchdog_health_corpus".to_owned(),
                    retained_records.to_string(),
                    retained_bytes.to_string(),
                    distinct_content.to_string(),
                    content_duplicates.to_string(),
                    reused_acknowledged_content.to_string(),
                    reactivated_after_receipt.to_string(),
                    acknowledged_sequence.to_string(),
                    unacknowledged_records.to_string(),
                    delivered_without_receipt.to_string(),
                    intents_without_receipt.to_string(),
                    stale_records.to_string(),
                    deferred_gap_reasons.to_string(),
                    newest_heartbeat_sequence.to_string(),
                    newest_sequence.to_string(),
                    newest_payload_class.clone(),
                    encode_identity(&digest_fields),
                ])
                .as_bytes(),
            ),
        })
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
        self.export_batch_impl(predecessor, high_water, limits, true)
    }

    /// Builds the owner-generated window the fenced intent route reconciles.
    ///
    /// The envelope is the same immutable window [`Self::export_batch`]
    /// builds — predecessor, full covered range, high-water, identity,
    /// digest, freshness — bound to the intent contour's own sink identity.
    /// The stored cursor may already be bound to the sibling export contour:
    /// this window enforces the stored sequence and lineage but not the
    /// stored sink binding, because it never advances the cursor and never
    /// compacts. Exactly-once stays with the per-record submit-once receipt
    /// the caller persists from the fenced route's acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] under the same conditions as
    /// [`Self::export_batch`], except a stored sink binding owned by the
    /// sibling export contour is not a failure.
    pub(crate) fn export_batch_for_intent_window(
        &self,
        predecessor: &WatchdogSpoolCursor,
        high_water: u64,
        limits: WatchdogSpoolExportLimits,
    ) -> Result<(WatchdogSpoolExportBatch, Vec<Vec<u8>>), SpoolError> {
        self.export_batch_impl(predecessor, high_water, limits, false)
    }

    fn export_batch_impl(
        &self,
        predecessor: &WatchdogSpoolCursor,
        high_water: u64,
        limits: WatchdogSpoolExportLimits,
        enforce_sink_binding: bool,
    ) -> Result<(WatchdogSpoolExportBatch, Vec<Vec<u8>>), SpoolError> {
        tracing::debug!(
            event = "watchdog.spool_export_attempted",
            observation = "attempted",
            "exporting spool batch without payload material"
        );
        limits.validate()?;
        validate_cursor(predecessor, high_water)?;
        let window = self.read_export_window_snapshot(
            predecessor,
            high_water,
            &limits,
            enforce_sink_binding,
        )?;
        if predecessor.acknowledged_sequence == high_water {
            let batch = build_empty_export_batch(predecessor, high_water)?;
            validate_batch(&batch, high_water)?;
            return Ok((batch, Vec::new()));
        }
        match window {
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
    fn read_export_window_snapshot(
        &self,
        predecessor: &WatchdogSpoolCursor,
        high_water: u64,
        limits: &WatchdogSpoolExportLimits,
        enforce_sink_binding: bool,
    ) -> Result<ExportWindow, SpoolError> {
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
        let last_sequence = validate_header_stream(&header, &table)?;
        let high_water_table = read.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!("high-water metadata is unavailable: {error}"))
        })?;
        let live_high_water = read_high_water(&high_water_table)?
            .ok_or_else(|| SpoolError::Corrupt("high-water metadata is missing".to_owned()))?;
        validate_high_water_last(&header, last_sequence, live_high_water)?;
        let stored = match read.open_table(SPOOL_EXPORT_CURSOR_TABLE) {
            Ok(cursor_table) => decode_export_cursor_value(&cursor_table)?,
            Err(redb::TableError::TableDoesNotExist(_)) => unbound_export_cursor(),
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        };
        if high_water > live_high_water {
            return Err(WatchdogSpoolReconciliationError::InvalidCursor.into());
        }
        // The intent reconciliation window never advances the shared cursor,
        // so it enforces the stored sequence and lineage but tolerates a
        // cursor the sibling export contour already bound to its own sink.
        // The export window keeps the sink binding because its
        // acknowledgement moves the cursor.
        if enforce_sink_binding {
            check_export_predecessor(&stored, predecessor)?;
        } else {
            check_window_sequence_binding(&stored, predecessor)?;
        }
        if predecessor.acknowledged_sequence == high_water {
            return Ok(ExportWindow::Ready(Vec::new()));
        }
        select_export_window(
            &table,
            predecessor.acknowledged_sequence,
            high_water,
            limits,
        )
    }

    /// Reads a validated spool snapshot for the bounded pending-intent query.
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

/// Storage encoding of a superseded deterministic-rule state row that recorded
/// no owner-issued admission order.
///
/// It exists so an existing row is read strictly and then explicitly
/// dispositioned, never reinterpreted as current state and never treated as
/// fresh empty state. Its retained wall-clock timestamp is carried forward as
/// diagnostic evidence and is never read as an order.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct WatchdogIntentRuleStateSupersededRecord {
    schema_version: u16,
    state: intent::GovernorIntentRuleStateSuperseded,
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
/// strictly as that revision's own shape and carried forward with an explicit
/// incomplete-history disposition, so a revision that recorded wall-clock time
/// but no owner-issued order is never read as if it had recorded an order. Any
/// other revision, and any row that does not decode, fails closed as corruption:
/// neither becomes fresh empty state, and a rule whose history cannot be read
/// never silently restarts its escalation.
fn decode_intent_rule_state(bytes: &[u8]) -> Result<intent::GovernorIntentRuleState, SpoolError> {
    let revision: WatchdogIntentRuleStateRevision =
        serde_json::from_slice(bytes).map_err(|error| {
            SpoolError::Corrupt(format!("watchdog intent rule state is invalid: {error}"))
        })?;
    match revision.schema_version {
        intent::INTENT_RULE_SCHEMA_VERSION => {
            let record: WatchdogIntentRuleStateRecord = decode_strict_rule_row(bytes)?;
            check_rule_row_revision(record.schema_version, record.state.schema_version)?;
            record.state.validate()?;
            Ok(record.state)
        }
        intent::INTENT_RULE_SUPERSEDED_SCHEMA_VERSION => {
            let record: WatchdogIntentRuleStateSupersededRecord = decode_strict_rule_row(bytes)?;
            check_rule_row_revision(record.schema_version, record.state.schema_version)?;
            let state = record.state.without_owner_order();
            state.validate()?;
            Ok(state)
        }
        intent::INTENT_RULE_LEGACY_SCHEMA_VERSION => {
            let record: WatchdogIntentRuleStateLegacyRecord = decode_strict_rule_row(bytes)?;
            check_rule_row_revision(record.schema_version, record.state.schema_version)?;
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

/// Decodes one rule row strictly into the exact shape its revision wrote.
fn decode_strict_rule_row<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, SpoolError> {
    serde_json::from_slice(bytes).map_err(|error| {
        SpoolError::Corrupt(format!("watchdog intent rule state is invalid: {error}"))
    })
}

/// Fails closed when a rule row's own storage revision disagrees with the
/// revision its carried state claims, so a row can never be reinterpreted under
/// a revision it was not written under.
fn check_rule_row_revision(row_revision: u16, state_revision: u16) -> Result<(), SpoolError> {
    if row_revision != state_revision {
        return Err(SpoolError::Corrupt(
            "watchdog intent rule state schema drifted from its storage row".to_owned(),
        ));
    }
    Ok(())
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

/// Storage encoding of the Watchdog-owned journal read position (#1755 W3).
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct StoredJournalCursorRecord {
    schema_version: u32,
    journal_id: u64,
    next_usn: u64,
}

/// Schema of [`StoredJournalCursorRecord`]; a stored row naming anything
/// else is refused rather than migrated silently.
const JOURNAL_CURSOR_SCHEMA_VERSION: u32 = 1;

/// Refuses an unusable journal-cursor volume label before any spool write.
fn validate_journal_cursor_volume(volume: &str) -> Result<(), SpoolError> {
    if volume.is_empty() || !volume.is_ascii() || volume.chars().any(char::is_control) {
        return Err(SpoolError::Corrupt(
            "journal cursor volume label is unusable".to_owned(),
        ));
    }
    Ok(())
}

/// Decodes one stored journal-cursor row into a resume position.
///
/// A row naming another schema or no journal identity is corrupt: resuming
/// from it would replay the wrong history as continuity.
fn decode_journal_cursor_record(
    record: &StoredJournalCursorRecord,
) -> Result<Option<eliot_platform_windows::UsnCursor>, SpoolError> {
    if record.schema_version != JOURNAL_CURSOR_SCHEMA_VERSION {
        return Err(SpoolError::Corrupt(format!(
            "stored journal cursor names unknown schema {}",
            record.schema_version
        )));
    }
    if record.journal_id == 0 {
        return Err(SpoolError::Corrupt(
            "stored journal cursor carries no journal identity".to_owned(),
        ));
    }
    Ok(Some(eliot_platform_windows::UsnCursor {
        journal_id: record.journal_id,
        next_usn: record.next_usn,
    }))
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

/// Reads the active installation identity out of the owner's own retained
/// runtime admission.
///
/// This is the single reader for the active side of every isolation fact, and it
/// is module-level `pub` only so the backup port in
/// [`crate::watchdog_composition`] compares against the same owner-issued read
/// instead of re-walking the manifest; the enclosing `watchdog_spool` module is
/// private to this crate, so no new public API leaves the binary. The value is
/// never received from a caller string:
/// `WatchdogSpool::open_runtime_binding` opens the live spool from exactly this
/// binding's Watchdog state root, so this is the same owner-issued fact that
/// decides where the live database is.
#[must_use]
pub fn owner_issued_active_installation(binding: &WatchdogRuntimeBinding) -> &str {
    binding
        .selected_manifest
        .runtime_launch
        .installation_epoch
        .installation
        .as_str()
}

/// Refuses a destination that names the active installation's own Watchdog state
/// root.
///
/// Identity inequality alone does not prove a different store. Two distinct
/// admitted identities can name one state root, and then an import would append
/// quarantined evidence into the active installation's own `watchdog.redb` —
/// overwriting live supervision history and reusing the active installation's
/// storage as a recovery target. Both roots below are owner-issued (the
/// destination's own approved manifest, and the active binding's own approved
/// manifest), so this comparison cannot be satisfied by presenting a convenient
/// string. The roots are compared with the same `windows_paths_equal` the
/// destination admission itself uses.
///
/// # Errors
///
/// Returns [`SpoolError::InvalidLease`] when the destination and the active
/// installation are one owner-issued state root.
fn reject_shared_active_state_root(
    destination: &AdmittedIsolatedDestination,
    active: &WatchdogRuntimeBinding,
) -> Result<(), SpoolError> {
    if windows_paths_equal(
        destination.watchdog_state_root(),
        active.watchdog_state_root(),
    ) {
        return Err(SpoolError::InvalidLease(
            "watchdog spool backup import refuses to run: the admitted isolated destination shares the active installation's Watchdog state root, so it is not a separate recovery target".to_owned(),
        ));
    }
    Ok(())
}

/// True when the destination installation still retains an unresolved
/// coverage-invalidating signal or intent.
///
/// Classification goes through the one owner the capture path uses
/// ([`backup::SpoolFenceEntryKind`]), so an import cannot disagree with a
/// snapshot about which records invalidate coverage. This import's own
/// `BACKUP_IMPORT_REASON_MARKER` quarantine records are excluded, and only
/// because they are the operation's own historical evidence: a repeated import
/// must still be able to observe its own `Duplicate` disposition rather than
/// blocking on what it wrote last time. Every other coverage-invalidating record
/// — a `Gap`, an unreconciled problem/incident intent, or a `Recovery` this
/// owner did not write — is an unresolved critical signal and blocks. The
/// records themselves are never dropped, reordered, or downgraded.
#[must_use]
fn has_unresolved_critical(retained: &[WatchdogSpoolEntry]) -> bool {
    retained.iter().any(|entry| {
        let is_own_quarantine = matches!(
            &entry.payload,
            WatchdogSpoolPayload::Recovery { reason, .. }
                if reason.starts_with(BACKUP_IMPORT_REASON_MARKER)
        );
        !is_own_quarantine
            && backup::SpoolFenceEntryKind::classify(&entry.payload).marks_incomplete()
    })
}

/// Collects the destination installation's own already-quarantined import
/// evidence as `(reason, corrupt_digest)` pairs.
///
/// These are the records an earlier import of this same owner wrote into the
/// destination spool; they are the destination's retained idempotency evidence
/// and are never dropped, reordered, or rewritten.
fn retained_import_quarantine(retained: &[WatchdogSpoolEntry]) -> Vec<(String, String)> {
    let mut quarantined: Vec<(String, String)> = Vec::new();
    for entry in retained {
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
    quarantined
}

/// Refuses a presented step chain that cannot be counted or is over the
/// bounded work ceiling.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the chain length is not representable as
/// the bounded step counter, or exceeds
/// [`backup::BACKUP_MAX_WORK_UNITS`].
fn validate_import_step_budget(steps: &[backup::SpoolRestoreStep]) -> Result<(), SpoolError> {
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
    Ok(())
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
/// Spool-local intents (`ProblemIntent`, `IncidentIntent`), Host attempts
/// (`HostAttempt`), and containment requests (`ContainmentRequest`) keep the
/// existing `Recovery` (gap-like) class here: the shared
/// `WatchdogSpoolPayloadKind` is intentionally not extended (out-of-lane
/// exhaustive matches would break). The class is used for retention and
/// compaction classification only — an intent's own fenced reconciliation runs
/// through the Kernel `watchdog-spool-batch-v1` intent route, never through this
/// tag. Compaction retains every one of these records regardless of class, so an
/// acknowledged intent, an attempt, and an emitted request are never removed and
/// stay linked to the Governor's later decision.
fn export_payload_kind(payload: &WatchdogSpoolPayload) -> WatchdogSpoolPayloadKind {
    match payload {
        WatchdogSpoolPayload::Heartbeat { .. } => WatchdogSpoolPayloadKind::Heartbeat,
        WatchdogSpoolPayload::Gap { .. } => WatchdogSpoolPayloadKind::Gap,
        WatchdogSpoolPayload::Recovery { .. }
        | WatchdogSpoolPayload::ProblemIntent { .. }
        | WatchdogSpoolPayload::IncidentIntent { .. }
        | WatchdogSpoolPayload::HostAttempt { .. }
        | WatchdogSpoolPayload::ContainmentRequest { .. } => WatchdogSpoolPayloadKind::Recovery,
    }
}

/// Checks the export predecessor against the stored Watchdog-owned cursor.
///
/// An unbound stored cursor accepts any shape-valid predecessor and binds it
/// in memory; a bound cursor requires the exact acknowledged sequence plus
/// identical owner identities, including the cursor revision.
/// Sequence and lineage binding shared by the export and intent windows.
///
/// Both contours read the same stored cursor progress, so both enforce the
/// schema, the acknowledged sequence, and the owner lineage. Only the sink
/// binding differs: the export contour advances the shared cursor and stays
/// bound to the sink that owns it, while the intent contour never advances
/// the cursor and must tolerate a cursor the sibling export contour bound.
/// See [`check_export_predecessor`].
fn check_window_sequence_binding(
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
    Ok(())
}

fn check_export_predecessor(
    stored: &WatchdogSpoolCursor,
    predecessor: &WatchdogSpoolCursor,
) -> Result<(), WatchdogSpoolReconciliationError> {
    // Full binding for the cursor-advancing export window: the shared
    // sequence and lineage binding plus the stored sink binding, so only
    // the sink that owns the bound cursor may advance it.
    check_window_sequence_binding(stored, predecessor)?;
    if !is_unbound_export_cursor(stored) && predecessor.sink_id != stored.sink_id {
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
fn select_export_window<T>(
    table: &T,
    acknowledged: u64,
    high_water: u64,
    limits: &WatchdogSpoolExportLimits,
) -> Result<ExportWindow, SpoolError>
where
    T: ReadableTable<u64, &'static [u8]>,
{
    let first_needed = acknowledged
        .checked_add(1)
        .ok_or(WatchdogSpoolReconciliationError::PredecessorMismatch)?;
    let item_cap_end = acknowledged
        .saturating_add(limits.max_items as u64)
        .min(high_water);
    let mut selected = Vec::new();
    let mut bytes_total: u64 = 0;
    let mut expected = first_needed;
    for item in table
        .range(first_needed..=item_cap_end)
        .map_err(|error| SpoolError::Database(error.to_string()))?
    {
        let (key, value) = item.map_err(|error| SpoolError::Database(error.to_string()))?;
        let entry = decode_entry(key.value(), value.value())?;
        if entry.sequence != expected {
            return Err(SpoolError::Corrupt(
                "watchdog spool retention no longer covers the export cursor; refusing to skip sequences"
                    .to_owned(),
            ));
        }
        let raw = encode_entry(&entry)?;
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
/// intent, a Host attempt, and a containment request are never compaction
/// candidates at any sequence: the original Watchdog record must stay retained so
/// the fenced Kernel record, the Governor's later decision, and the request this
/// Watchdog emitted stay forensically linked to it, and retention pressure
/// eviction is the only thing that may ever drop it.
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
        .filter(|entry| !attempt::is_forensically_linked_payload(&entry.payload))
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

#[cfg(test)]
mod shared_manifest_retention_tests {
    use super::*;
    use eliot_evaluation_contracts::ObservationCoverageManifest;

    use crate::coverage_manifest_projection::{
        CoverageManifestOutcome, publish_interval_coverage_manifest,
    };
    use crate::observation_coverage::{
        IntervalCoveragePublisher, ObservationChannel, channel_capability,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn test_spool(name: &str) -> Result<WatchdogSpool, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "eliot-watchdog-manifest-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        Ok(WatchdogSpool::open_test(&path)?)
    }

    /// The owner's own fully observed interval, published through the same
    /// wrapper the tick calls, so the retained row is the production payload
    /// rather than a hand-built fixture.
    fn published_manifest() -> Result<ObservationCoverageManifest, Box<dyn std::error::Error>> {
        let mut publisher = IntervalCoveragePublisher::new(1_000);
        for channel in ObservationChannel::ALL {
            for class in channel_capability(channel).supported_classes {
                publisher.record(channel, *class);
            }
        }
        let report = publisher.close(2_000);
        match publish_interval_coverage_manifest(
            Some("installation-1755"),
            Some(&"a".repeat(64)),
            &report,
        ) {
            CoverageManifestOutcome::Published { manifest, .. } => Ok(*manifest),
            CoverageManifestOutcome::Omitted(reason) => {
                Err(format!("both owner identities are present, got omission {reason}").into())
            }
        }
    }

    /// A published manifest retains and reads back identical: the payload
    /// reaches durable owner evidence (#1755 W6).
    #[test]
    fn published_manifest_round_trips_through_owner_spool() -> TestResult {
        let spool = test_spool("round-trip")?;
        let manifest = published_manifest()?;
        spool.retain_shared_coverage_manifest(&manifest)?;
        assert_eq!(spool.read_shared_coverage_manifest()?, Some(manifest));
        Ok(())
    }

    /// No interval retained yet reads as none, never as an empty manifest.
    #[test]
    fn absent_manifest_reads_none() -> TestResult {
        let spool = test_spool("absent")?;
        assert_eq!(spool.read_shared_coverage_manifest()?, None);
        Ok(())
    }

    /// An invalid manifest is refused whole and the previously retained row
    /// stands untouched: refusal repairs nothing and invents nothing.
    #[test]
    fn invalid_manifest_is_refused_and_prior_row_stands() -> TestResult {
        let spool = test_spool("refused")?;
        let manifest = published_manifest()?;
        spool.retain_shared_coverage_manifest(&manifest)?;
        let mut broken = manifest.clone();
        broken.expected_event_sources_and_event_classes.clear();
        assert!(broken.validate().is_err());
        assert!(spool.retain_shared_coverage_manifest(&broken).is_err());
        assert_eq!(spool.read_shared_coverage_manifest()?, Some(manifest));
        Ok(())
    }

    /// A stored row that no longer parses is refused as corrupt rather than
    /// served as evidence: fail closed, never a best-effort manifest.
    #[test]
    fn corrupt_row_is_refused_not_served() -> TestResult {
        let spool = test_spool("corrupt")?;
        let write = spool
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        {
            let mut table = write
                .open_table(SPOOL_COVERAGE_MANIFEST_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            table
                .insert(SPOOL_COVERAGE_MANIFEST_KEY, b"not-json".as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
        }
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        assert!(spool.read_shared_coverage_manifest().is_err());
        Ok(())
    }

    /// A retained journal cursor reads back identical: the resume position
    /// reaches durable owner evidence (#1755 W3).
    #[test]
    fn journal_cursor_round_trips_through_owner_spool() -> TestResult {
        let spool = test_spool("journal-cursor-round-trip")?;
        assert_eq!(spool.read_journal_cursor("\\\\.\\C:")?, None);
        let cursor = eliot_platform_windows::UsnCursor {
            journal_id: 0x01dc_2182_7839_5a3f,
            next_usn: 0x20bb_b2c5d0,
        };
        spool.retain_journal_cursor("\\\\.\\C:", &cursor)?;
        assert_eq!(spool.read_journal_cursor("\\\\.\\C:")?, Some(cursor));
        Ok(())
    }

    /// A zero journal identity is refused whole and the previously retained
    /// row stands untouched: a position in no journal is not a position.
    #[test]
    fn zero_journal_identity_is_refused_and_prior_row_stands() -> TestResult {
        let spool = test_spool("journal-cursor-refused")?;
        let cursor = eliot_platform_windows::UsnCursor {
            journal_id: 0x01dc_2182_7839_5a3f,
            next_usn: 7,
        };
        spool.retain_journal_cursor("\\\\.\\C:", &cursor)?;
        let zero = eliot_platform_windows::UsnCursor {
            journal_id: 0,
            next_usn: 9,
        };
        assert!(spool.retain_journal_cursor("\\\\.\\C:", &zero).is_err());
        assert!(spool.retain_journal_cursor("", &cursor).is_err());
        assert_eq!(spool.read_journal_cursor("\\\\.\\C:")?, Some(cursor));
        Ok(())
    }

    /// A stored cursor row that no longer parses is refused as corrupt
    /// rather than served as a position: resuming from decay would replay
    /// the wrong history as continuity.
    #[test]
    fn corrupt_journal_cursor_row_is_refused() -> TestResult {
        let spool = test_spool("journal-cursor-corrupt")?;
        let write = spool
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        {
            let mut table = write
                .open_table(SPOOL_JOURNAL_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            table
                .insert("\\\\.\\C:", b"not-json".as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
        }
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        assert!(spool.read_journal_cursor("\\\\.\\C:").is_err());
        Ok(())
    }
}
