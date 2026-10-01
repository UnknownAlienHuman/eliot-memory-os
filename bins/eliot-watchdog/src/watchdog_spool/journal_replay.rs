//! Registered-scope filesystem journal replay for the Watchdog's own spool.
//!
//! Architecture: ARCH-WDG-01, ARCH-WDG-02, ARCH-PORT-01.
//! Implementation: I8.2 (filesystem change journal / watched paths, including
//! persisted cursor replay for registered Windows WorkScopes), I8.1 (the
//! Watchdog consumes the journal through a read-only port and owns its spool).
//!
//! One spool-owned cursor record per actual journal/source and registered scope
//! lineage, in the same `watchdog.redb` file as the records it describes. It
//! is a separate table, not a second file and not a second database: the owner
//! keeps its single writer and its single file. The cursor row binds the
//! volume/journal identity, the scope root and generation, the committed
//! position and the replay horizon. Every replay validates the live source
//! against that binding before reuse, reads one bounded page, normalizes and
//! retains its observations and gaps durably, then advances the cursor in the
//! same owner transaction that retained them.
//!
//! Crash contract: the retain and the cursor advance commit atomically, so a
//! crash before commit retains nothing and moves nothing (the next replay
//! re-reads the same range, skipping nothing), and a crash after commit finds
//! both durable (the next replay resumes past the committed position, so no
//! duplicate is counted as new independent evidence). A write transaction never
//! spans journal I/O: the page is read outside any transaction and the commit
//! transaction re-validates the cursor row byte-for-byte, so a stale page fails
//! closed instead of retaining against a moved cursor.
//!
//! Explicit gaps, never silent reset: journal replacement, journal wrap,
//! regressed horizon, denied source access, changed scope generation, missing
//! ranges and unsupported records each retain a named gap row and rebind or
//! resume explicitly. No path resets to the newest position and reports full
//! coverage.
//!
//! Retention: normalized evidence rows are filed under a per-cursor insertion
//! sequence, so eviction is oldest-first by direct key with no scan and no
//! pointer that can climb across a rebind. Reaching the per-cursor row ceiling
//! evicts the oldest observation rows and retains an `EVIDENCE_EVICTED_RANGE`
//! gap naming them, mirroring the main spool's pressure-gap precedent. Gap
//! rows are never evicted: running out of room for a gap fails closed instead
//! of silently eating it.
//!
//! Scope, stated exactly: this owner retains event evidence (USN, bounded
//! path, path digest, change class) and explicit gaps. It performs no
//! attribution: a file change is not principal identity, tool intent, or task
//! membership here, and the rows carry no content, intent, or principal field
//! to misread. Attribution against registered identities is the W4 consumer's
//! work over these rows, not this module's.
//!
//! STITCH: the production callers are the supervision tick in
//! [`crate::watchdog_composition`] (drive
//! [`WatchdogSpool::replay_registered_journal_page`] once per tick for each
//! admitted registered scope) and the USN FFI source in
//! `eliot-platform-windows` (implement [`JournalPageSource`]; Windows FFI
//! stays out of the Watchdog, which remains a read-only consumer of the
//! port). Mapping retained replay evidence into the coverage publisher's
//! `JOURNAL_REPLAYED` disposition needs the `observation_coverage.rs`
//! increment: this module never writes a coverage disposition, and a replayed
//! interval is not a live sample.

use std::path::Path;

use eliot_contracts::sha256_hex;
use redb::{ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};

use crate::SpoolError;

use super::WatchdogSpool;

/// Storage revision of one durable journal cursor row.
///
/// A future revision bump refuses to mix cursor generations instead of
/// reinterpreting them.
pub(crate) const JOURNAL_REPLAY_CURSOR_SCHEMA_VERSION: u16 = 1;

/// Storage revision of one durable journal evidence row.
///
/// Distinct from the cursor revision so a future evidence-shape change refuses
/// to reinterpret existing rows instead of mixing generations.
pub(crate) const JOURNAL_REPLAY_EVIDENCE_SCHEMA_VERSION: u16 = 1;

/// Cursor table inside the same `watchdog.redb` file.
///
/// One row per actual journal/source and registered scope lineage, keyed by
/// the digest of the scope lineage (see [`journal_cursor_key`]). The row
/// carries the full binding and is cross-checked against its key on every
/// read, so the key is a lookup hint and the stored binding is authoritative.
pub(crate) const JOURNAL_REPLAY_CURSOR_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_watchdog_spool_journal_cursor_v1");

/// Evidence table inside the same `watchdog.redb` file.
///
/// Rows are filed under [`journal_evidence_key`] (cursor key plus per-cursor
/// insertion sequence) and carry their cursor key for the cross-check. The
/// sequence is dense: rows are never deleted except by oldest-first eviction,
/// so every sequence below the cursor's next sequence exists exactly once.
pub(crate) const JOURNAL_REPLAY_EVIDENCE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_watchdog_spool_journal_evidence_v1");

/// Maximum accepted length for one persisted journal, volume, or scope
/// identity string.
///
/// Identities are short OS- or installer-bound names. The cap keeps cursor
/// rows tiny and fails closed on corrupt oversized values instead of growing
/// them without bound.
pub(crate) const JOURNAL_IDENTITY_MAX_BYTES: usize = 1024;

/// Maximum accepted length for one retained journal path, in bytes.
///
/// A record whose path exceeds this cannot be retained faithfully, so it is
/// reported as an [`JOURNAL_GAP_UNSUPPORTED_RECORD`] gap, never truncated.
pub(crate) const JOURNAL_PATH_MAX_BYTES: usize = 4096;

/// Hard ceiling for the journal records consumed from one page read.
///
/// 256 records keep one replay bounded against the spool's own export window
/// (`EXPORT_MAX_ITEMS`); a caller window above it is rejected instead of
/// silently clamped so an exact retry of the same window stays equivalent.
pub(crate) const JOURNAL_REPLAY_MAX_RECORDS: usize = 256;

/// Hard ceiling for the estimated bytes of one page.
///
/// 512 KiB mirrors the spool's export byte ceiling, so any single retained
/// path always fits while one page can never pin the tick with an unbounded
/// window.
pub(crate) const JOURNAL_REPLAY_MAX_BYTES: u64 = 512 * 1024;

/// Lower bound for a usable page byte window.
///
/// One maximum-size path plus per-record overhead must always fit, so a page
/// window below this cannot make progress and is rejected.
pub(crate) const JOURNAL_REPLAY_MIN_BYTES: u64 = 8 * 1024;

/// Hard ceiling for registered journal cursors.
///
/// One cursor exists per admitted registered scope lineage. Reaching the
/// ceiling refuses the 65th lineage explicitly instead of evicting another
/// scope's cursor: historical cursor rows are retained evidence of prior
/// generations, never deletion candidates.
pub(crate) const JOURNAL_REPLAY_MAX_CURSORS: usize = 64;

/// Hard ceiling for retained evidence rows under one cursor.
///
/// Reaching it evicts the oldest observation rows first and retains an
/// [`JOURNAL_GAP_EVICTED_RANGE`] gap naming them. Gap rows are never evicted:
/// a page whose gaps do not fit fails closed instead of silently eating them.
pub(crate) const JOURNAL_REPLAY_MAX_EVIDENCE_ROWS: u64 = 4096;

/// The live journal no longer matches the cursor's bound journal identity.
///
/// Retained with the old committed position and the new journal's lowest
/// valid position; the cursor rebinds explicitly to the new journal.
pub(crate) const JOURNAL_GAP_REPLACED: &str = "JOURNAL_REPLACED";

/// The scope lineage moved to a new generation.
///
/// Recorded in the new generation's own cursor row. The old generation's row
/// and history are untouched: generation history is preserved, not rewritten.
pub(crate) const JOURNAL_GAP_SCOPE_GENERATION_CHANGED: &str = "SCOPE_GENERATION_CHANGED";

/// The journal wrapped or shrank past the committed position.
///
/// Retained with the committed position and the resume position; the
/// unrecoverable range between them is named, never skipped silently.
pub(crate) const JOURNAL_GAP_WRAP: &str = "JOURNAL_WRAP_MISSING_RANGE";

/// The journal source refused the page read.
///
/// Retained once per committed position; the cursor does not move, so the
/// next replay resumes at the same position instead of skipping it.
pub(crate) const JOURNAL_GAP_SOURCE_DENIED: &str = "SOURCE_DENIED";

/// Journal records that cannot be normalized or retained.
///
/// One coalesced row per page names the USN span, the record count, and the
/// first unsupported cause: unknown change class or overlong path.
pub(crate) const JOURNAL_GAP_UNSUPPORTED_RECORD: &str = "UNSUPPORTED_JOURNAL_RECORD";

/// The oldest observation rows evicted under retention pressure.
///
/// Names the evicted USN span and count, mirroring the main spool's explicit
/// pressure gap instead of silently deleting unexported evidence.
pub(crate) const JOURNAL_GAP_EVICTED_RANGE: &str = "EVIDENCE_EVICTED_RANGE";

/// True for a stored gap code this owner may have written.
fn is_known_journal_gap_code(code: &str) -> bool {
    matches!(
        code,
        JOURNAL_GAP_REPLACED
            | JOURNAL_GAP_SCOPE_GENERATION_CHANGED
            | JOURNAL_GAP_WRAP
            | JOURNAL_GAP_SOURCE_DENIED
            | JOURNAL_GAP_UNSUPPORTED_RECORD
            | JOURNAL_GAP_EVICTED_RANGE
    )
}

/// Normalized file-change class of one journal record.
///
/// The port vocabulary, not Windows constants: the future USN FFI source
/// classifies into these, so no `USN_REASON_*` value ever enters the
/// Watchdog. Anything the source cannot classify is
/// [`JournalChange::Unsupported`], which the driver retains as an explicit
/// gap instead of an observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JournalChange {
    /// The journal reports a creation under the watched scope.
    Created,
    /// The journal reports data or metadata modification.
    Modified,
    /// The journal reports a rename into, out of, or within the scope.
    Renamed,
    /// The journal reports a deletion.
    Deleted,
    /// The journal record carries a change class this owner does not
    /// normalize. The raw OS code travels only this far: it names the gap
    /// row and never becomes an observation.
    Unsupported {
        /// Raw OS change code, for the gap row.
        code: u32,
    },
}

impl JournalChange {
    /// Returns the stable retained name of a normalizable change.
    ///
    /// Returns `None` for [`JournalChange::Unsupported`]: unsupported records
    /// have no observation name, only a gap.
    pub(crate) const fn as_str(self) -> Option<&'static str> {
        match self {
            Self::Created => Some("created"),
            Self::Modified => Some("modified"),
            Self::Renamed => Some("renamed"),
            Self::Deleted => Some("deleted"),
            Self::Unsupported { .. } => None,
        }
    }
}

/// True for a retained observation reason this owner may have written.
fn is_known_journal_reason(reason: &str) -> bool {
    matches!(reason, "created" | "modified" | "renamed" | "deleted")
}

/// One journal record offered by the source port.
///
/// `usn` is the journal's own sequence: strictly increasing within a page and
/// the resume key of the cursor. `path` is the in-scope path the journal
/// names for the change: event evidence for the W4 consumer's scope-membership
/// resolution, never file contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalRecord {
    /// Journal sequence number of this record.
    pub usn: u64,
    /// In-scope path named by the journal record.
    pub path: String,
    /// Normalized change class, or unclassifiable.
    pub change: JournalChange,
}

/// One bounded journal page offered by the source port.
///
/// Records are in strictly increasing `usn` order. `next_usn` is the position
/// a committed page advances the cursor to; it is never below the last record
/// and never above the source's advertised horizon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalPage {
    /// Records of this page, strictly increasing by `usn`.
    pub records: Vec<JournalRecord>,
    /// Resume position when this page commits.
    pub next_usn: u64,
    /// True when the source reports no further journal past this page.
    pub end_of_journal: bool,
}

/// Live source binding presented by the journal port.
///
/// Untrusted until the driver validates its shape and, on reuse, its equality
/// with the stored cursor binding. `lowest_valid_usn` is the oldest position
/// the journal can still serve; `horizon_usn` is the newest position it
/// advertises. Both move only forward for one journal identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalSourceBinding {
    /// OS-stable identity of the volume hosting the journal.
    pub volume_identity: String,
    /// OS-stable identity of the journal itself (survives ordinary restarts;
    /// changes when the journal is deleted and recreated).
    pub journal_identity: String,
    /// Oldest servable journal position.
    pub lowest_valid_usn: u64,
    /// Newest advertised journal position.
    pub horizon_usn: u64,
}

/// Registered scope lineage the caller replays.
///
/// The registration the cursor row is keyed by: one admitted Windows
/// WorkScope root plus the generation of its registration. Attribution of
/// retained events against these identities is the W4 consumer's work; this
/// struct is the persistence binding that makes one row exactly one lineage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalScopeLineage {
    /// Absolute registered scope root the journal events are watched under.
    pub scope_root: String,
    /// Generation of the scope registration.
    pub scope_generation: String,
}

impl JournalScopeLineage {
    /// Refuses a lineage that cannot key exactly one cursor row.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the root is not absolute or
    /// either value is empty or exceeds
    /// [`JOURNAL_IDENTITY_MAX_BYTES`].
    pub(crate) fn validate(&self) -> Result<(), SpoolError> {
        if self.scope_root.len() > JOURNAL_IDENTITY_MAX_BYTES
            || self.scope_generation.len() > JOURNAL_IDENTITY_MAX_BYTES
        {
            return Err(SpoolError::Corrupt(
                "journal replay scope lineage exceeds the bounded identity frame".to_owned(),
            ));
        }
        if self.scope_generation.is_empty() {
            return Err(SpoolError::Corrupt(
                "journal replay scope generation must be non-empty".to_owned(),
            ));
        }
        if !Path::new(&self.scope_root).is_absolute() {
            return Err(SpoolError::Corrupt(
                "journal replay scope root must be absolute".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Bounded window for one journal page read.
///
/// Both caps apply together and the source enforces them; the driver
/// re-checks the page against them, so a source that over-serves fails closed
/// instead of retaining an unbounded page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JournalReplayLimits {
    /// Maximum journal records consumed from one page.
    pub max_records: usize,
    /// Maximum estimated bytes of one page.
    pub max_bytes: u64,
}

impl Default for JournalReplayLimits {
    fn default() -> Self {
        Self {
            max_records: JOURNAL_REPLAY_MAX_RECORDS,
            max_bytes: JOURNAL_REPLAY_MAX_BYTES,
        }
    }
}

impl JournalReplayLimits {
    /// Rejects unbounded or unprogressable windows before any journal read.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when either bound is zero or above its
    /// hard ceiling.
    pub(crate) fn validate(&self) -> Result<(), SpoolError> {
        if self.max_records == 0 || self.max_records > JOURNAL_REPLAY_MAX_RECORDS {
            return Err(SpoolError::Corrupt(
                "journal replay record window is outside its hard ceiling".to_owned(),
            ));
        }
        if self.max_bytes < JOURNAL_REPLAY_MIN_BYTES || self.max_bytes > JOURNAL_REPLAY_MAX_BYTES {
            return Err(SpoolError::Corrupt(
                "journal replay byte window is outside its hard ceiling".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Read-only journal port the Watchdog consumes.
///
/// The future USN FFI source implements this in `eliot-platform-windows`;
/// the Watchdog never touches journal handles, privileges, or Windows
/// constants directly. Object-safe so the driver takes `&dyn` without
/// naming an implementation.
pub(crate) trait JournalPageSource: Send + Sync {
    /// Returns the live source binding for validation against the cursor.
    fn journal_binding(&self) -> JournalSourceBinding;
    /// Reads at most one bounded page starting just past `from_usn`.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the journal is denied, unavailable, or
    /// unreadable. A failure retains an explicit gap without moving the
    /// cursor; it never skips the unread range.
    fn read_page(
        &self,
        from_usn: u64,
        limits: JournalReplayLimits,
    ) -> Result<JournalPage, SpoolError>;
}

/// Refuses a source binding whose shape cannot be bound or compared.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when either identity is empty or exceeds
/// [`JOURNAL_IDENTITY_MAX_BYTES`], or the advertised window is inverted.
fn validate_source_binding(binding: &JournalSourceBinding) -> Result<(), SpoolError> {
    if binding.volume_identity.is_empty() || binding.journal_identity.is_empty() {
        return Err(SpoolError::Corrupt(
            "journal replay source binding requires non-empty volume and journal identities"
                .to_owned(),
        ));
    }
    if binding.volume_identity.len() > JOURNAL_IDENTITY_MAX_BYTES
        || binding.journal_identity.len() > JOURNAL_IDENTITY_MAX_BYTES
    {
        return Err(SpoolError::Corrupt(
            "journal replay source binding exceeds the bounded identity frame".to_owned(),
        ));
    }
    if binding.lowest_valid_usn > binding.horizon_usn {
        return Err(SpoolError::Corrupt(
            "journal replay source window is inverted".to_owned(),
        ));
    }
    Ok(())
}

/// Derives the ledger key one cursor row is filed under.
///
/// The key binds the scope lineage only: the journal binding is validated
/// state inside the row, not key material, so a journal replacement rebinds
/// the same row explicitly while a generation change files a new row and
/// preserves the old generation's history. The row stores the full lineage
/// and is cross-checked against this key on every read.
pub(crate) fn journal_cursor_key(scope_root: &str, scope_generation: &str) -> String {
    sha256_hex(format!("journal-cursor/v1\x00{scope_root}\x00{scope_generation}").as_bytes())
}

/// Derives the ledger key one evidence row is filed under.
///
/// `sequence` is the cursor's per-row insertion sequence: dense and
/// oldest-first, so eviction deletes by direct key with no scan.
fn journal_evidence_key(cursor_key: &str, sequence: u64) -> String {
    format!("{cursor_key}/e/{sequence:020}")
}

/// Spool-owned cursor record for one journal/source and scope lineage.
///
/// `committed_usn` is the resume position: every journal record at or below
/// it is either retained or explicitly gapped. `oldest_evidence_seq` and
/// `next_evidence_seq` delimit the live evidence rows: empty when equal, and
/// their difference is the retained row count, so no counter can drift from
/// the rows it counts.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct StoredJournalCursor {
    schema_version: u16,
    volume_identity: String,
    journal_identity: String,
    scope_root: String,
    scope_generation: String,
    committed_usn: u64,
    horizon_usn: u64,
    oldest_evidence_seq: u64,
    next_evidence_seq: u64,
    denied_gap_recorded: bool,
    denied_gap_usn: u64,
}

impl StoredJournalCursor {
    /// Re-checks the stored row: shape, identities, lineage, and window.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the schema is unsupported, an
    /// identity or lineage value is unusable, the committed position lies
    /// past the horizon, or the evidence sequence is inverted.
    fn validate(&self) -> Result<(), SpoolError> {
        if self.schema_version != JOURNAL_REPLAY_CURSOR_SCHEMA_VERSION {
            return Err(SpoolError::Corrupt(
                "journal replay cursor schema is unsupported".to_owned(),
            ));
        }
        if self.volume_identity.is_empty()
            || self.journal_identity.is_empty()
            || self.volume_identity.len() > JOURNAL_IDENTITY_MAX_BYTES
            || self.journal_identity.len() > JOURNAL_IDENTITY_MAX_BYTES
        {
            return Err(SpoolError::Corrupt(
                "journal replay cursor journal binding is unusable".to_owned(),
            ));
        }
        if self.scope_root.len() > JOURNAL_IDENTITY_MAX_BYTES
            || self.scope_generation.is_empty()
            || self.scope_generation.len() > JOURNAL_IDENTITY_MAX_BYTES
            || !Path::new(&self.scope_root).is_absolute()
        {
            return Err(SpoolError::Corrupt(
                "journal replay cursor scope lineage is unusable".to_owned(),
            ));
        }
        if self.committed_usn > self.horizon_usn {
            return Err(SpoolError::Corrupt(
                "journal replay cursor committed position is past its horizon".to_owned(),
            ));
        }
        if self.oldest_evidence_seq == 0
            || self.next_evidence_seq == 0
            || self.oldest_evidence_seq > self.next_evidence_seq
        {
            return Err(SpoolError::Corrupt(
                "journal replay cursor evidence sequence is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    /// Live retained evidence rows filed under this cursor.
    fn evidence_rows(&self) -> u64 {
        self.next_evidence_seq
            .saturating_sub(self.oldest_evidence_seq)
    }
}

/// Durably retained journal evidence: one normalized observation or one
/// explicit gap.
///
/// Observations carry the USN, the bounded in-scope path, its digest, and the
/// change class: event evidence for scope-membership resolution, with no
/// content, intent, or principal field to misread. Gaps name the code, the
/// position recorded at, the resume position, and the affected record count.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum StoredJournalEvidence {
    Observation {
        schema_version: u16,
        cursor_key: String,
        usn: u64,
        path: String,
        path_digest: String,
        reason: String,
        observed_at_ms: u64,
    },
    Gap {
        schema_version: u16,
        cursor_key: String,
        gap: String,
        at_usn: u64,
        resume_usn: u64,
        count: u64,
        observed_at_ms: u64,
    },
}

impl StoredJournalEvidence {
    /// Re-checks one stored row filed under the caller's cursor key.
    ///
    /// Observation digests are recomputed, not trusted: a row whose digest
    /// disagrees with its path fails closed rather than attributing a path
    /// to the wrong bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the row names a different cursor,
    /// carries an unknown reason or gap code, or violates its shape.
    fn validate(&self, cursor_key: &str) -> Result<(), SpoolError> {
        match self {
            Self::Observation {
                schema_version,
                cursor_key: row_cursor,
                usn: _,
                path,
                path_digest,
                reason,
                observed_at_ms: _,
            } => {
                if *schema_version != JOURNAL_REPLAY_EVIDENCE_SCHEMA_VERSION {
                    return Err(SpoolError::Corrupt(
                        "journal replay evidence schema is unsupported".to_owned(),
                    ));
                }
                if row_cursor != cursor_key {
                    return Err(SpoolError::Corrupt(
                        "journal replay evidence row does not match the cursor it is filed under"
                            .to_owned(),
                    ));
                }
                if !is_known_journal_reason(reason) {
                    return Err(SpoolError::Corrupt(
                        "journal replay evidence reason is unknown".to_owned(),
                    ));
                }
                if path.is_empty() || path.len() > JOURNAL_PATH_MAX_BYTES {
                    return Err(SpoolError::Corrupt(
                        "journal replay evidence path is outside the bounded frame".to_owned(),
                    ));
                }
                if sha256_hex(path.as_bytes()) != *path_digest {
                    return Err(SpoolError::Corrupt(
                        "journal replay evidence path digest does not match its path".to_owned(),
                    ));
                }
                Ok(())
            }
            Self::Gap {
                schema_version,
                cursor_key: row_cursor,
                gap,
                at_usn: _,
                resume_usn: _,
                count,
                observed_at_ms: _,
            } => {
                if *schema_version != JOURNAL_REPLAY_EVIDENCE_SCHEMA_VERSION {
                    return Err(SpoolError::Corrupt(
                        "journal replay evidence schema is unsupported".to_owned(),
                    ));
                }
                if row_cursor != cursor_key {
                    return Err(SpoolError::Corrupt(
                        "journal replay evidence row does not match the cursor it is filed under"
                            .to_owned(),
                    ));
                }
                if !is_known_journal_gap_code(gap) {
                    return Err(SpoolError::Corrupt(
                        "journal replay evidence gap code is unknown".to_owned(),
                    ));
                }
                let record_loss = matches!(
                    gap.as_str(),
                    JOURNAL_GAP_WRAP | JOURNAL_GAP_UNSUPPORTED_RECORD | JOURNAL_GAP_EVICTED_RANGE
                );
                if record_loss == (*count == 0) {
                    return Err(SpoolError::Corrupt(
                        "journal replay evidence gap count disagrees with its code".to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Reads one stored cursor row from a caller's already-open table.
///
/// A missing row reports `None` for a lineage this owner has never bound; a
/// present row is decoded strictly and cross-checked against the ledger key
/// it was read under. A row that fails any of that fails closed: an unreadable
/// cursor must never be treated as a fresh one, or a restart would re-read
/// already-committed ranges as new evidence or skip them silently.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the stored row does not decode, is not
/// canonical, or does not match its ledger key, and [`SpoolError::Database`]
/// when the row cannot be read.
fn read_journal_cursor<T>(
    table: &T,
    ledger_key: &str,
) -> Result<Option<StoredJournalCursor>, SpoolError>
where
    T: ReadableTable<&'static str, &'static [u8]>,
{
    let Some(value) = table
        .get(ledger_key)
        .map_err(|error| SpoolError::Database(error.to_string()))?
    else {
        return Ok(None);
    };
    let cursor: StoredJournalCursor = serde_json::from_slice(value.value()).map_err(|error| {
        SpoolError::Corrupt(format!("journal replay cursor row is invalid: {error}"))
    })?;
    cursor.validate()?;
    if journal_cursor_key(&cursor.scope_root, &cursor.scope_generation) != ledger_key {
        return Err(SpoolError::Corrupt(
            "journal replay cursor row does not match the ledger key it is filed under".to_owned(),
        ));
    }
    Ok(Some(cursor))
}

/// Persists one validated cursor row inside a caller's write transaction.
///
/// It never opens a transaction of its own, so a caller commits the retained
/// evidence rows and this cursor advance as one atomic change.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the row is not canonical, and
/// [`SpoolError::Database`] or [`SpoolError::Serialization`] when the row
/// cannot be written.
fn write_journal_cursor(
    write: &WriteTransaction,
    ledger_key: &str,
    cursor: &StoredJournalCursor,
) -> Result<(), SpoolError> {
    cursor.validate()?;
    if journal_cursor_key(&cursor.scope_root, &cursor.scope_generation) != ledger_key {
        return Err(SpoolError::Corrupt(
            "journal replay cursor row does not match the ledger key it is filed under".to_owned(),
        ));
    }
    let bytes =
        serde_json::to_vec(cursor).map_err(|error| SpoolError::Serialization(error.to_string()))?;
    let mut table = write
        .open_table(JOURNAL_REPLAY_CURSOR_TABLE)
        .map_err(|error| SpoolError::Database(error.to_string()))?;
    table
        .insert(ledger_key, bytes.as_slice())
        .map_err(|error| SpoolError::Database(error.to_string()))?;
    drop(table);
    Ok(())
}

/// Persists one validated evidence row inside a caller's write transaction.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the row is not canonical for its
/// ledger key, and [`SpoolError::Database`] or [`SpoolError::Serialization`]
/// when the row cannot be written.
fn write_journal_evidence(
    write: &WriteTransaction,
    cursor_key: &str,
    sequence: u64,
    evidence: &StoredJournalEvidence,
) -> Result<(), SpoolError> {
    evidence.validate(cursor_key)?;
    let ledger_key = journal_evidence_key(cursor_key, sequence);
    let bytes = serde_json::to_vec(evidence)
        .map_err(|error| SpoolError::Serialization(error.to_string()))?;
    let mut table = write
        .open_table(JOURNAL_REPLAY_EVIDENCE_TABLE)
        .map_err(|error| SpoolError::Database(error.to_string()))?;
    table
        .insert(ledger_key.as_str(), bytes.as_slice())
        .map_err(|error| SpoolError::Database(error.to_string()))?;
    drop(table);
    Ok(())
}

/// Removes one evicted evidence row inside a caller's write transaction.
///
/// The row is read back first so the eviction gap can name the evicted USN
/// span; a missing sequence fails closed, because the dense-sequence
/// invariant is what makes eviction terminate without a scan.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the sequence holds no live row, and
/// [`SpoolError::Database`] when the row cannot be read or removed.
fn evict_journal_evidence(
    write: &WriteTransaction,
    cursor_key: &str,
    sequence: u64,
) -> Result<StoredJournalEvidence, SpoolError> {
    let ledger_key = journal_evidence_key(cursor_key, sequence);
    let mut table = write
        .open_table(JOURNAL_REPLAY_EVIDENCE_TABLE)
        .map_err(|error| SpoolError::Database(error.to_string()))?;
    let raw: Vec<u8> = {
        let Some(value) = table
            .get(ledger_key.as_str())
            .map_err(|error| SpoolError::Database(error.to_string()))?
        else {
            return Err(SpoolError::Corrupt(
                "journal replay evidence sequence has a hole; refusing to evict past it".to_owned(),
            ));
        };
        value.value().to_vec()
    };
    let evidence: StoredJournalEvidence =
        serde_json::from_slice(raw.as_slice()).map_err(|error| {
            SpoolError::Corrupt(format!("journal replay evidence row is invalid: {error}"))
        })?;
    evidence.validate(cursor_key)?;
    table
        .remove(ledger_key.as_str())
        .map_err(|error| SpoolError::Database(error.to_string()))?;
    drop(table);
    Ok(evidence)
}

/// Observation mode of one committed replay call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JournalReplayDisposition {
    /// The page committed to its `next_usn` and the source reports journal
    /// end: the interval up to the horizon is replayed.
    PageComplete,
    /// The page committed to its `next_usn` but the journal holds more: the
    /// caller ticks again for the next bounded page.
    PageHasMore,
    /// A binding, wrap, or access gap was retained (or a fresh cursor bound)
    /// instead of a page: no records were skipped and none were duplicated.
    GapRebound,
}

/// Durable result of one bounded replay call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalReplayOutcome {
    /// Ledger key of the cursor row this call committed.
    pub cursor_key: String,
    /// Committed resume position after this call.
    pub committed_usn: u64,
    /// Replay horizon after this call.
    pub horizon_usn: u64,
    /// Normalized observations retained by this call.
    pub observations_retained: u32,
    /// Explicit gaps retained by this call.
    pub gaps_retained: u32,
    /// What this call proved about the interval.
    pub disposition: JournalReplayDisposition,
}

/// Read-only replay decision from the stored cursor and the live binding.
enum JournalReplayDecision {
    /// No cursor row exists for this lineage: bind one at the journal's
    /// lowest valid position. Nothing was ever committed, so nothing is
    /// lost and no gap is owed.
    BindFresh,
    /// The stored journal identity no longer matches the live source, or the
    /// live horizon regressed under the same identity: the journal was
    /// replaced. Retain [`JOURNAL_GAP_REPLACED`] and rebind explicitly.
    RebindAfterGap,
    /// The committed position fell below the journal's lowest valid position
    /// (wrap) or past its horizon: retain [`JOURNAL_GAP_WRAP`] and resume
    /// explicitly at the lowest valid position.
    ResumeAfterWrap,
    /// The binding matches and the committed position is still servable:
    /// read one bounded page.
    ReadPage,
}

/// Decides one replay call from the stored cursor and the live binding.
///
/// Pure classifier, no I/O: every caller re-derives the same decision from
/// the same inputs, and every branch names its gap instead of resetting
/// silently.
fn decide_journal_replay(
    stored: Option<&StoredJournalCursor>,
    binding: &JournalSourceBinding,
    scope: &JournalScopeLineage,
) -> JournalReplayDecision {
    let Some(cursor) = stored else {
        return JournalReplayDecision::BindFresh;
    };
    if cursor.volume_identity != binding.volume_identity
        || cursor.journal_identity != binding.journal_identity
        || cursor.scope_root != scope.scope_root
        || cursor.scope_generation != scope.scope_generation
        || binding.horizon_usn < cursor.horizon_usn
    {
        return JournalReplayDecision::RebindAfterGap;
    }
    if cursor.committed_usn < binding.lowest_valid_usn || cursor.committed_usn > binding.horizon_usn
    {
        return JournalReplayDecision::ResumeAfterWrap;
    }
    JournalReplayDecision::ReadPage
}

impl WatchdogSpool {
    /// Replays one bounded page of a registered scope's filesystem journal.
    ///
    /// One spool-owned cursor row per journal/source and scope lineage binds
    /// the volume/journal identity, scope lineage, committed position, and
    /// horizon; the live source is validated against it before reuse, one
    /// bounded page is normalized and retained with its gaps, and the cursor
    /// advances in the same owner transaction. See the module documentation
    /// for the crash contract and the explicit-gap table.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when any input, stored row, source
    /// binding, or page violates its bound or fails validation; the cursor
    /// never moves on such a failure. Returns the source's own error when a
    /// page read fails after its explicit gap is retained durably.
    pub(crate) fn replay_registered_journal_page(
        &self,
        source: &dyn JournalPageSource,
        scope: &JournalScopeLineage,
        limits: JournalReplayLimits,
        observed_at_ms: u64,
    ) -> Result<JournalReplayOutcome, SpoolError> {
        limits.validate()?;
        scope.validate()?;
        let cursor_key = journal_cursor_key(&scope.scope_root, &scope.scope_generation);
        let binding = source.journal_binding();
        validate_source_binding(&binding)?;

        let stored = {
            let read = self
                .database
                .begin_read()
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            match read.open_table(JOURNAL_REPLAY_CURSOR_TABLE) {
                Ok(table) => read_journal_cursor(&table, cursor_key.as_str())?,
                Err(redb::TableError::TableDoesNotExist(_)) => None,
                Err(error) => return Err(SpoolError::Database(error.to_string())),
            }
        };

        let outcome = match decide_journal_replay(stored.as_ref(), &binding, scope) {
            JournalReplayDecision::BindFresh => {
                debug_assert!(stored.is_none());
                self.bind_fresh_journal_cursor(&cursor_key, scope, &binding, observed_at_ms)
            }
            JournalReplayDecision::RebindAfterGap => {
                let previous = stored.as_ref().ok_or_else(|| {
                    SpoolError::Corrupt(
                        "journal replay rebind decided without a stored cursor".to_owned(),
                    )
                })?;
                self.rebind_journal_cursor(&cursor_key, previous, &binding, observed_at_ms)
            }
            JournalReplayDecision::ResumeAfterWrap => {
                let previous = stored.as_ref().ok_or_else(|| {
                    SpoolError::Corrupt(
                        "journal replay resume decided without a stored cursor".to_owned(),
                    )
                })?;
                self.resume_journal_cursor_after_wrap(
                    &cursor_key,
                    previous,
                    &binding,
                    observed_at_ms,
                )
            }
            JournalReplayDecision::ReadPage => {
                let previous = stored.as_ref().ok_or_else(|| {
                    SpoolError::Corrupt(
                        "journal replay page read decided without a stored cursor".to_owned(),
                    )
                })?;
                self.replay_clean_journal_page(&CleanJournalReplay {
                    source,
                    cursor_key: cursor_key.as_str(),
                    previous,
                    binding: &binding,
                    limits,
                    observed_at_ms,
                })
            }
        };
        match &outcome {
            Ok(committed) => {
                tracing::debug!(
                    event = "watchdog.journal_replay_committed",
                    observation = "replayed",
                    cursor_key = committed.cursor_key.as_str(),
                    committed_usn = committed.committed_usn,
                    horizon_usn = committed.horizon_usn,
                    observations_retained = committed.observations_retained,
                    gaps_retained = committed.gaps_retained,
                    disposition = ?committed.disposition,
                    "committed one bounded journal page with its cursor advance"
                );
            }
            Err(error) => {
                tracing::debug!(
                    event = "watchdog.journal_replay_failed",
                    observation = "rejected",
                    error = error.to_string(),
                    "refused one journal replay call without moving its cursor"
                );
            }
        }
        outcome
    }

    /// Binds the first cursor row for a lineage at the journal's lowest valid
    /// position.
    ///
    /// A lineage that was never bound has no committed position to lose, so
    /// starting at the oldest servable record is complete from the earliest
    /// available evidence, not a reset. When the same scope root was already
    /// bound under a different generation, the lineage discontinuity is
    /// retained as an explicit [`JOURNAL_GAP_SCOPE_GENERATION_CHANGED`] gap in
    /// the new row; the old generation's row and history are untouched.
    fn bind_fresh_journal_cursor(
        &self,
        cursor_key: &str,
        scope: &JournalScopeLineage,
        binding: &JournalSourceBinding,
        observed_at_ms: u64,
    ) -> Result<JournalReplayOutcome, SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let prior_generation = {
            let table = write
                .open_table(JOURNAL_REPLAY_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            if read_journal_cursor(&table, cursor_key)?.is_some() {
                return Err(SpoolError::Corrupt(
                    "journal replay bind raced a concurrent bind for the same lineage".to_owned(),
                ));
            }
            let mut keys = Vec::new();
            for item in table
                .iter()
                .map_err(|error| SpoolError::Database(error.to_string()))?
            {
                let (key, _) = item.map_err(|error| SpoolError::Database(error.to_string()))?;
                keys.push(key.value().to_owned());
            }
            if keys.len() >= JOURNAL_REPLAY_MAX_CURSORS {
                return Err(SpoolError::Corrupt(
                    "journal replay refuses a further registered scope cursor past its ceiling"
                        .to_owned(),
                ));
            }
            // Same root, different generation: the lineage moved. Every
            // sibling row is read strictly, so a corrupt sibling fails the
            // bind closed instead of filing a new lineage beside garbage.
            let mut prior = false;
            for key in &keys {
                if let Some(sibling) = read_journal_cursor(&table, key.as_str())? {
                    if sibling.scope_root == scope.scope_root
                        && sibling.scope_generation != scope.scope_generation
                    {
                        prior = true;
                    }
                }
            }
            prior
        };
        let mut cursor = StoredJournalCursor {
            schema_version: JOURNAL_REPLAY_CURSOR_SCHEMA_VERSION,
            volume_identity: binding.volume_identity.clone(),
            journal_identity: binding.journal_identity.clone(),
            scope_root: scope.scope_root.clone(),
            scope_generation: scope.scope_generation.clone(),
            committed_usn: binding.lowest_valid_usn,
            horizon_usn: binding.horizon_usn,
            oldest_evidence_seq: 1,
            next_evidence_seq: 1,
            denied_gap_recorded: false,
            denied_gap_usn: 0,
        };
        let mut generation_gaps: Vec<StoredJournalEvidence> = Vec::new();
        if prior_generation {
            generation_gaps.push(StoredJournalEvidence::Gap {
                schema_version: JOURNAL_REPLAY_EVIDENCE_SCHEMA_VERSION,
                cursor_key: cursor_key.to_owned(),
                gap: JOURNAL_GAP_SCOPE_GENERATION_CHANGED.to_owned(),
                at_usn: 0,
                resume_usn: binding.lowest_valid_usn,
                count: 0,
                observed_at_ms,
            });
        }
        retain_journal_rows(
            &write,
            cursor_key,
            &mut cursor,
            &[],
            &generation_gaps,
            observed_at_ms,
        )?;
        write_journal_cursor(&write, cursor_key, &cursor)?;
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let gaps_retained = u32::try_from(generation_gaps.len()).map_err(|_| {
            SpoolError::Corrupt("journal replay gap count exceeds its counter".to_owned())
        })?;
        Ok(JournalReplayOutcome {
            cursor_key: cursor_key.to_owned(),
            committed_usn: cursor.committed_usn,
            horizon_usn: cursor.horizon_usn,
            observations_retained: 0,
            gaps_retained,
            disposition: if prior_generation {
                JournalReplayDisposition::GapRebound
            } else {
                JournalReplayDisposition::PageHasMore
            },
        })
    }

    /// Rebinds a cursor row to a replaced journal with an explicit gap.
    ///
    /// The old journal's identity no longer names the live source, so its
    /// committed position is meaningless against the new one. The gap names
    /// the old position and the new resume position with a zero record count:
    /// the unobservable range of a replaced journal is unknowable, and a zero
    /// count says exactly that instead of inventing one.
    fn rebind_journal_cursor(
        &self,
        cursor_key: &str,
        previous: &StoredJournalCursor,
        binding: &JournalSourceBinding,
        observed_at_ms: u64,
    ) -> Result<JournalReplayOutcome, SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let stored = {
            let table = write
                .open_table(JOURNAL_REPLAY_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            read_journal_cursor(&table, cursor_key)?
        };
        let stored = stored.ok_or_else(|| {
            SpoolError::Corrupt("journal replay cursor vanished before its rebind".to_owned())
        })?;
        if stored != *previous {
            return Err(SpoolError::Corrupt(
                "journal replay cursor moved before its rebind; refusing a stale rebind".to_owned(),
            ));
        }
        let at_usn = stored.committed_usn;
        let mut cursor = stored;
        let gap = StoredJournalEvidence::Gap {
            schema_version: JOURNAL_REPLAY_EVIDENCE_SCHEMA_VERSION,
            cursor_key: cursor_key.to_owned(),
            gap: JOURNAL_GAP_REPLACED.to_owned(),
            at_usn,
            resume_usn: binding.lowest_valid_usn,
            count: 0,
            observed_at_ms,
        };
        cursor.volume_identity = binding.volume_identity.clone();
        cursor.journal_identity = binding.journal_identity.clone();
        cursor.committed_usn = binding.lowest_valid_usn;
        cursor.horizon_usn = binding.horizon_usn;
        cursor.denied_gap_recorded = false;
        cursor.denied_gap_usn = 0;
        retain_journal_rows(&write, cursor_key, &mut cursor, &[], &[gap], observed_at_ms)?;
        write_journal_cursor(&write, cursor_key, &cursor)?;
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        Ok(JournalReplayOutcome {
            cursor_key: cursor_key.to_owned(),
            committed_usn: cursor.committed_usn,
            horizon_usn: cursor.horizon_usn,
            observations_retained: 0,
            gaps_retained: 1,
            disposition: JournalReplayDisposition::GapRebound,
        })
    }

    /// Resumes a cursor row past a wrapped journal with an explicit gap.
    ///
    /// The range between the committed position and the journal's lowest
    /// valid position is unrecoverable: the gap names it with its exact
    /// record distance, and the cursor resumes explicitly at the lowest
    /// valid position instead of resetting silently to the newest.
    fn resume_journal_cursor_after_wrap(
        &self,
        cursor_key: &str,
        previous: &StoredJournalCursor,
        binding: &JournalSourceBinding,
        observed_at_ms: u64,
    ) -> Result<JournalReplayOutcome, SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let stored = {
            let table = write
                .open_table(JOURNAL_REPLAY_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            read_journal_cursor(&table, cursor_key)?
        };
        let stored = stored.ok_or_else(|| {
            SpoolError::Corrupt("journal replay cursor vanished before its resume".to_owned())
        })?;
        if stored != *previous {
            return Err(SpoolError::Corrupt(
                "journal replay cursor moved before its resume; refusing a stale resume".to_owned(),
            ));
        }
        let lost = if stored.committed_usn < binding.lowest_valid_usn {
            binding
                .lowest_valid_usn
                .saturating_sub(stored.committed_usn)
        } else {
            stored
                .committed_usn
                .saturating_sub(binding.lowest_valid_usn)
        };
        if lost == 0 {
            return Err(SpoolError::Corrupt(
                "journal replay wrap decided without a lost range".to_owned(),
            ));
        }
        let mut cursor = stored;
        let gap = StoredJournalEvidence::Gap {
            schema_version: JOURNAL_REPLAY_EVIDENCE_SCHEMA_VERSION,
            cursor_key: cursor_key.to_owned(),
            gap: JOURNAL_GAP_WRAP.to_owned(),
            at_usn: cursor.committed_usn,
            resume_usn: binding.lowest_valid_usn,
            count: lost,
            observed_at_ms,
        };
        cursor.committed_usn = binding.lowest_valid_usn;
        cursor.horizon_usn = binding.horizon_usn;
        cursor.denied_gap_recorded = false;
        cursor.denied_gap_usn = 0;
        retain_journal_rows(&write, cursor_key, &mut cursor, &[], &[gap], observed_at_ms)?;
        write_journal_cursor(&write, cursor_key, &cursor)?;
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        Ok(JournalReplayOutcome {
            cursor_key: cursor_key.to_owned(),
            committed_usn: cursor.committed_usn,
            horizon_usn: cursor.horizon_usn,
            observations_retained: 0,
            gaps_retained: 1,
            disposition: JournalReplayDisposition::GapRebound,
        })
    }
}

/// Inputs of one clean page replay: the bound cursor row and the live source
/// it was validated against.
///
/// One struct instead of six parameters: the commit transaction requires the
/// whole bundle unchanged, so the bundle travels as one value from the
/// decision to the commit.
#[derive(Clone, Copy)]
struct CleanJournalReplay<'a> {
    source: &'a dyn JournalPageSource,
    cursor_key: &'a str,
    previous: &'a StoredJournalCursor,
    binding: &'a JournalSourceBinding,
    limits: JournalReplayLimits,
    observed_at_ms: u64,
}

impl WatchdogSpool {
    /// Reads one page past the committed position and commits it with the
    /// cursor advance, or retains the denied-access gap without moving.
    ///
    /// The page is read outside any transaction; the commit transaction
    /// requires the cursor row byte-identical to the decision snapshot, so a
    /// page read against a moved cursor fails closed instead of retaining
    /// against the wrong position.
    fn replay_clean_journal_page(
        &self,
        call: &CleanJournalReplay<'_>,
    ) -> Result<JournalReplayOutcome, SpoolError> {
        let CleanJournalReplay {
            source,
            cursor_key,
            previous,
            binding,
            limits,
            observed_at_ms,
        } = *call;
        // `JournalReplayLimits` and `u64` are `Copy`; the references stay
        // borrowed from the caller's bundle.
        let page = match source.read_page(previous.committed_usn, limits) {
            Ok(page) => page,
            Err(error) => {
                return self.retain_denied_gap(cursor_key, previous, error, observed_at_ms);
            }
        };
        Self::validate_page(&page, previous, binding, &limits)?;
        let mut observations = Vec::new();
        let mut unsupported: Vec<&JournalRecord> = Vec::new();
        for record in &page.records {
            match record.change.as_str() {
                Some(reason)
                    if record.path.len() <= JOURNAL_PATH_MAX_BYTES && !record.path.is_empty() =>
                {
                    observations.push(StoredJournalEvidence::Observation {
                        schema_version: JOURNAL_REPLAY_EVIDENCE_SCHEMA_VERSION,
                        cursor_key: cursor_key.to_owned(),
                        usn: record.usn,
                        path: record.path.clone(),
                        path_digest: sha256_hex(record.path.as_bytes()),
                        reason: reason.to_owned(),
                        observed_at_ms,
                    });
                }
                _ => unsupported.push(record),
            }
        }
        let mut gaps = Vec::new();
        if !unsupported.is_empty() {
            let first = unsupported.first().ok_or_else(|| {
                SpoolError::Corrupt("journal replay unsupported span is empty".to_owned())
            })?;
            let last = unsupported.last().ok_or_else(|| {
                SpoolError::Corrupt("journal replay unsupported span is empty".to_owned())
            })?;
            let count = u64::try_from(unsupported.len()).map_err(|_| {
                SpoolError::Corrupt(
                    "journal replay unsupported span exceeds its counter".to_owned(),
                )
            })?;
            gaps.push(StoredJournalEvidence::Gap {
                schema_version: JOURNAL_REPLAY_EVIDENCE_SCHEMA_VERSION,
                cursor_key: cursor_key.to_owned(),
                gap: JOURNAL_GAP_UNSUPPORTED_RECORD.to_owned(),
                at_usn: first.usn,
                resume_usn: last.usn,
                count,
                observed_at_ms,
            });
        }
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let stored = {
            let table = write
                .open_table(JOURNAL_REPLAY_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            read_journal_cursor(&table, cursor_key)?
        };
        let stored = stored.ok_or_else(|| {
            SpoolError::Corrupt("journal replay cursor vanished before its page commit".to_owned())
        })?;
        if stored != *previous {
            return Err(SpoolError::Corrupt(
                "journal replay cursor moved before its page commit; refusing a stale page"
                    .to_owned(),
            ));
        }
        let mut cursor = stored;
        cursor.committed_usn = page.next_usn;
        cursor.denied_gap_recorded = false;
        cursor.denied_gap_usn = 0;
        retain_journal_rows(
            &write,
            cursor_key,
            &mut cursor,
            &observations,
            &gaps,
            observed_at_ms,
        )?;
        write_journal_cursor(&write, cursor_key, &cursor)?;
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let observations_retained = u32::try_from(observations.len()).map_err(|_| {
            SpoolError::Corrupt("journal replay observation count exceeds its counter".to_owned())
        })?;
        let gaps_retained = u32::try_from(gaps.len()).map_err(|_| {
            SpoolError::Corrupt("journal replay gap count exceeds its counter".to_owned())
        })?;
        Ok(JournalReplayOutcome {
            cursor_key: cursor_key.to_owned(),
            committed_usn: cursor.committed_usn,
            horizon_usn: cursor.horizon_usn,
            observations_retained,
            gaps_retained,
            disposition: if page.end_of_journal {
                JournalReplayDisposition::PageComplete
            } else {
                JournalReplayDisposition::PageHasMore
            },
        })
    }

    /// Retains the denied-access gap without moving the cursor.
    ///
    /// The first denial at a position retains one explicit gap row and
    /// reports the source's own error, so the outage is visible and the
    /// position is not skipped. A repeated denial at the same position finds
    /// its gap already durable and reports a rebound without writing again,
    /// so an outage cannot flood the evidence table and evict real evidence.
    fn retain_denied_gap(
        &self,
        cursor_key: &str,
        previous: &StoredJournalCursor,
        error: SpoolError,
        observed_at_ms: u64,
    ) -> Result<JournalReplayOutcome, SpoolError> {
        if previous.denied_gap_recorded && previous.denied_gap_usn == previous.committed_usn {
            return Ok(JournalReplayOutcome {
                cursor_key: cursor_key.to_owned(),
                committed_usn: previous.committed_usn,
                horizon_usn: previous.horizon_usn,
                observations_retained: 0,
                gaps_retained: 0,
                disposition: JournalReplayDisposition::GapRebound,
            });
        }
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let stored = {
            let table = write
                .open_table(JOURNAL_REPLAY_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            read_journal_cursor(&table, cursor_key)?
        };
        let stored = stored.ok_or_else(|| {
            SpoolError::Corrupt("journal replay cursor vanished before its denied gap".to_owned())
        })?;
        if stored != *previous {
            return Err(SpoolError::Corrupt(
                "journal replay cursor moved before its denied gap; refusing a stale gap"
                    .to_owned(),
            ));
        }
        let mut cursor = stored;
        let gap = StoredJournalEvidence::Gap {
            schema_version: JOURNAL_REPLAY_EVIDENCE_SCHEMA_VERSION,
            cursor_key: cursor_key.to_owned(),
            gap: JOURNAL_GAP_SOURCE_DENIED.to_owned(),
            at_usn: cursor.committed_usn,
            resume_usn: cursor.committed_usn,
            count: 0,
            observed_at_ms,
        };
        cursor.denied_gap_recorded = true;
        cursor.denied_gap_usn = cursor.committed_usn;
        retain_journal_rows(&write, cursor_key, &mut cursor, &[], &[gap], observed_at_ms)?;
        write_journal_cursor(&write, cursor_key, &cursor)?;
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        Err(error)
    }

    /// Strictly validates one offered page before anything is retained.
    ///
    /// Pure validator, no I/O: records must be strictly increasing past the
    /// committed position and within the advertised horizon, the resume
    /// position must chain from the records, and the page must fit the limits
    /// the caller set. Any violation fails closed with nothing retained and
    /// the cursor unmoved.
    fn validate_page(
        page: &JournalPage,
        cursor: &StoredJournalCursor,
        binding: &JournalSourceBinding,
        limits: &JournalReplayLimits,
    ) -> Result<(), SpoolError> {
        if page.records.len() > limits.max_records {
            return Err(SpoolError::Corrupt(
                "journal replay page exceeds its record window".to_owned(),
            ));
        }
        let mut estimated: u64 = 64;
        for record in &page.records {
            let path_len = u64::try_from(record.path.len()).map_err(|_| {
                SpoolError::Corrupt("journal replay path length exceeds its counter".to_owned())
            })?;
            estimated = estimated
                .checked_add(path_len.checked_add(64).ok_or_else(|| {
                    SpoolError::Corrupt("journal replay page size overflow".to_owned())
                })?)
                .ok_or_else(|| {
                    SpoolError::Corrupt("journal replay page size overflow".to_owned())
                })?;
        }
        if estimated > limits.max_bytes {
            return Err(SpoolError::Corrupt(
                "journal replay page exceeds its byte window".to_owned(),
            ));
        }
        let mut floor = cursor.committed_usn;
        for record in &page.records {
            if record.usn <= floor {
                return Err(SpoolError::Corrupt(
                    "journal replay page restates or reorders its records".to_owned(),
                ));
            }
            if record.usn > binding.horizon_usn {
                return Err(SpoolError::Corrupt(
                    "journal replay page reaches past the advertised horizon".to_owned(),
                ));
            }
            floor = record.usn;
        }
        if page.next_usn < floor {
            return Err(SpoolError::Corrupt(
                "journal replay page resume does not chain from its records".to_owned(),
            ));
        }
        if page.next_usn > binding.horizon_usn {
            return Err(SpoolError::Corrupt(
                "journal replay page resume reaches past the advertised horizon".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Retains one call's rows with oldest-first eviction under the ceiling.
///
/// Eviction frees exactly the room the incoming rows need and retains one
/// [`JOURNAL_GAP_EVICTED_RANGE`] gap naming the evicted USN span when it
/// freed anything. The dense insertion sequence makes every eviction a
/// direct-key delete: no scan, no climbing, deterministic termination.
/// Gap rows are never chosen for eviction; when even the gaps do not fit,
/// the call fails closed instead of silently eating them.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the incoming rows cannot be counted,
/// the evidence sequence breaks, or the ceiling has no room for the gaps,
/// and [`SpoolError::Database`] or [`SpoolError::Serialization`] when a row
/// cannot be written.
fn retain_journal_rows(
    write: &WriteTransaction,
    cursor_key: &str,
    cursor: &mut StoredJournalCursor,
    observations: &[StoredJournalEvidence],
    gaps: &[StoredJournalEvidence],
    observed_at_ms: u64,
) -> Result<(), SpoolError> {
    let incoming = u64::try_from(observations.len()).map_err(|_| {
        SpoolError::Corrupt("journal replay observation count exceeds its counter".to_owned())
    })?;
    let incoming = incoming
        .checked_add(u64::try_from(gaps.len()).map_err(|_| {
            SpoolError::Corrupt("journal replay gap count exceeds its counter".to_owned())
        })?)
        .ok_or_else(|| SpoolError::Corrupt("journal replay incoming count overflow".to_owned()))?;
    let mut evicted_usns: Vec<u64> = Vec::new();
    while cursor.evidence_rows().saturating_add(incoming) > JOURNAL_REPLAY_MAX_EVIDENCE_ROWS {
        let sequence = cursor.oldest_evidence_seq;
        let evicted = evict_journal_evidence(write, cursor_key, sequence)?;
        let usn = match &evicted {
            StoredJournalEvidence::Observation { usn, .. } => *usn,
            StoredJournalEvidence::Gap { .. } => {
                return Err(SpoolError::Corrupt(
                    "journal replay eviction reached a gap row; gaps are never evicted".to_owned(),
                ));
            }
        };
        evicted_usns.push(usn);
        cursor.oldest_evidence_seq = cursor.oldest_evidence_seq.saturating_add(1);
        let evicted_count = u64::try_from(evicted_usns.len()).map_err(|_| {
            SpoolError::Corrupt("journal replay evicted count exceeds its counter".to_owned())
        })?;
        if evicted_count > JOURNAL_REPLAY_MAX_EVIDENCE_ROWS {
            return Err(SpoolError::Corrupt(
                "journal replay eviction did not converge".to_owned(),
            ));
        }
    }
    let mut evicted_gap: Vec<StoredJournalEvidence> = Vec::new();
    if !evicted_usns.is_empty() {
        let first = evicted_usns.first().ok_or_else(|| {
            SpoolError::Corrupt("journal replay evicted span is empty".to_owned())
        })?;
        let last = evicted_usns.last().ok_or_else(|| {
            SpoolError::Corrupt("journal replay evicted span is empty".to_owned())
        })?;
        let count = u64::try_from(evicted_usns.len()).map_err(|_| {
            SpoolError::Corrupt("journal replay evicted count exceeds its counter".to_owned())
        })?;
        evicted_gap.push(StoredJournalEvidence::Gap {
            schema_version: JOURNAL_REPLAY_EVIDENCE_SCHEMA_VERSION,
            cursor_key: cursor_key.to_owned(),
            gap: JOURNAL_GAP_EVICTED_RANGE.to_owned(),
            at_usn: *first,
            resume_usn: *last,
            count,
            observed_at_ms,
        });
    }
    // At most one eviction gap exists per call and the loop freed at least
    // one row whenever it runs, so the ceiling check below is exact: a call
    // whose gaps still do not fit fails closed rather than dropping them.
    let total_incoming = incoming
        .checked_add(u64::try_from(evicted_gap.len()).map_err(|_| {
            SpoolError::Corrupt("journal replay evicted gap count exceeds its counter".to_owned())
        })?)
        .ok_or_else(|| SpoolError::Corrupt("journal replay incoming count overflow".to_owned()))?;
    if cursor.evidence_rows().saturating_add(total_incoming) > JOURNAL_REPLAY_MAX_EVIDENCE_ROWS {
        return Err(SpoolError::Corrupt(
            "journal replay evidence ceiling has no room for this page's gaps".to_owned(),
        ));
    }
    for evidence in observations
        .iter()
        .chain(gaps.iter())
        .chain(evicted_gap.iter())
    {
        let sequence = cursor.next_evidence_seq;
        write_journal_evidence(write, cursor_key, sequence, evidence)?;
        cursor.next_evidence_seq = cursor.next_evidence_seq.checked_add(1).ok_or_else(|| {
            SpoolError::Corrupt("journal replay evidence sequence exhausted".to_owned())
        })?;
    }
    Ok(())
}
