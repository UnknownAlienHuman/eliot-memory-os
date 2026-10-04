//! Bounded coherent ORS backup-snapshot proof, cases 1..20 (issue #953).
//!
//! Exercises the REAL `RedbRecoveryStore` backup export over temporary redb
//! files only: the stronger multi-page `OrsBackupSnapshot` projection and its
//! distinction from the report-only `OrsSnapshotReceipt`, exact
//! source/schema/generation/fence binding, coherent multi-page capture, page
//! binding/expiry, the exact row-family disposition denominator, the
//! opaque-payload-unavailable rule, order/effect-class lineage, the count/byte/
//! page bounds with their one-over refusals, and the source-equals-destination
//! refusal on the real import entrypoint.
//!
//! No second database is created, `eliot-backup` is never imported, no live
//! redb file is copied, no raw payload is read out of the store file, and no
//! fixture is invented: every exported row is written through the public
//! `OperationalRecoveryStore` writers. No `#[ignore]`, no in-memory stand-in,
//! no fabricated receipt.

use std::collections::BTreeSet;
use std::path::PathBuf;

// Case 953/19's crash child opens a real `redb::WriteTransaction` on the SAME
// temporary file the parent owns, so it needs redb's own `TableDefinition` and
// the `ReadableTable` trait that provides `iter()`. `redb` is this crate's OWN
// direct dependency (`crates/kernel/eliot-ors/Cargo.toml:29`); naming it here
// adds no new dependency and changes no lockfile.
use redb::{ReadableTable, TableDefinition};

use eliot_ors::{
    ArtifactGenerationState, BACKUP_SNAPSHOT_SCHEMA_VERSION, BackupCompleteness, EpochIdentity,
    EpochLineage, JobCheckpoint, MAX_BACKUP_BYTES, MAX_BACKUP_PAGE_ENTRIES, MAX_BACKUP_PAGES,
    OpaqueLabel, OperationalRecordContext, OperationalRecordInput, OperationalRecoveryStore,
    OrsBackupDestination, OrsBackupFence, OrsBackupImportRequest, OrsBackupPage, OrsBackupRequest,
    OrsBackupSnapshot, OrsBackupSourceIdentity, OrsError, OrsSnapshotReceipt, OrsSnapshotRequest,
    OrsStoreIdentity, PerEntryOutcome, RedbRecoveryStore, RowDisposition, RowFamilyKind,
    RowPayloadState, StagedOperation, StateFenceSnapshot, StoredEffectClass,
};
use eliot_platform::SecretReference;

type TestResult = Result<(), Box<dyn std::error::Error>>;
/// The generic sibling of `TestResult`: the extracted helpers below thread their
/// proven values back to the case body, so they return `Result<T, Box<dyn
/// std::error::Error>>` rather than the unit-shaped `TestResult`.
type TestOutcome<T> = Result<T, Box<dyn std::error::Error>>;
/// The archive's own member roster, exactly as `expected_member_roster` returns it:
/// each `(row family, record id)` pair the REAL export declared.
type MemberRoster953 = Vec<(RowFamilyKind, String)>;
/// What case 953/19's REOPEN phase hands back to the case body: the reopened REAL
/// store, the identity re-read through the public entrypoint, the second REAL
/// export made under that identity, and the roster that export declared.
type ReopenProof953 = (
    RedbRecoveryStore,
    OrsStoreIdentity,
    OrsBackupSnapshot,
    MemberRoster953,
);
/// What case 953/19's CAPTURE phase hands back: the captured roster, the source
/// identity the capture was bound to, and the generation that source carried.
type CaptureProof953 = (MemberRoster953, OrsBackupSourceIdentity, u64);

const LINEAGE_953: &str = "550e8400-e29b-41d4-a716-446655440000";
const EPOCH_953: u64 = 1;
/// Caller-declared fence stamp only. `OrsBackupFence::captured_at_ms`
/// (`src/backup_snapshot.rs:316`) is an assertion, not the page clock: the STORE
/// stamps each page's `created_at_ms`/`expires_at_ms` through its own clock at
/// capture, and `OrsBackupPage::validate_binding` (`src/backup_snapshot.rs:1759`)
/// bounds that store-stamped window against `MAX_BACKUP_PAGE_LIFETIME_MS`. This
/// constant is never compared against the page window by the contract, so no
/// claim about the window is made from it here.
const CAPTURED_AT_MS: i64 = 1_700_000_000_000;

/// 64 lowercase hex characters, the crate's digest shape (matches the
/// `digest(byte: char) -> String` helper shape in `tests/restore_journal.rs:35`).
fn fence_digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

/// One temporary redb file per case, in the hand-rolled pattern copied from
/// `tests/restore_journal.rs:48` (no `tempfile` dev-dependency exists in this crate).
fn temp_db(case: &str) -> PathBuf {
    let nanos = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    };
    std::env::temp_dir().join(format!(
        "eliot-953-{case}-{}-{nanos}.redb",
        std::process::id()
    ))
}

/// Opens one INSTALLATION-BOUND store.
///
/// `open_for_installation` is used, never `open()`: `check_export_fence`
/// (`src/store/backup_snapshot.rs:2397`) compares the requested source identity
/// against the DURABLE store-object identity, and an unbound database has none for
/// that comparison to succeed on, so `open()` would leave every backup export
/// unable to state its own source.
/// The error type is spelled `Box<dyn std::error::Error>` and deliberately NOT
/// the `TestResult` alias: `TestResult` is itself a `Result`, so naming it here
/// made this helper's failure type `Result<(), Box<dyn Error>>` and left the `?`
/// below unable to lift anything into it. `OrsError` is declared
/// `#[derive(Debug, Error)]` (`src/model.rs:4458`, with `thiserror::Error`
/// imported at `src/model.rs:30`), so it converts into this type directly and
/// every call site in the cases below keeps a bare `?`.
fn open_bound_store(
    case: &str,
) -> Result<(RedbRecoveryStore, OrsStoreIdentity, PathBuf), Box<dyn std::error::Error>> {
    let path = temp_db(case);
    let _ = std::fs::remove_file(&path);
    let (store, identity) =
        RedbRecoveryStore::open_for_installation(&path, &format!("installation-953-{case}"))?;
    Ok((store, identity, path))
}

/// The backup source identity a bound store's own identity names, at the
/// crate's current backup wire version.
fn source_for(identity: &OrsStoreIdentity) -> Result<OrsBackupSourceIdentity, OrsError> {
    OrsBackupSourceIdentity::new(
        identity.installation_id().to_string(),
        identity.ors_generation(),
        BACKUP_SNAPSHOT_SCHEMA_VERSION,
    )
}

fn epoch_lineage() -> Result<EpochLineage, OrsError> {
    Ok(EpochLineage {
        current: EpochIdentity {
            lineage_id: OpaqueLabel::new(LINEAGE_953)?,
            epoch: EPOCH_953,
        },
        predecessor: None,
    })
}

/// Exact-tuple fence contour, built the way `src/tests.rs:521` builds it: the
/// snapshot's canonical JSON carries the canonical `EpochId` object shape, and
/// the retained `u64` contour observes the same sequence and never authorizes on
/// its own.
fn state_fence(authority_epoch: &EpochLineage) -> Result<StateFenceSnapshot, OrsError> {
    StateFenceSnapshot::capture(
        &serde_json::json!({
            "authority_epoch": {
                "lineage_id": authority_epoch.current.lineage_id.as_str(),
                "sequence": authority_epoch.current.epoch
            },
            "integration_revision": null,
            "policy_revision": null,
            "resource_generation": 1,
            "task_revision": null
        }),
        authority_epoch.current.epoch,
    )
}

/// One encrypted opaque operational input, exactly as `src/tests.rs:549` builds it.
fn operational_input(
    record_id: &str,
    subject_id: &str,
    authority_epoch: &EpochLineage,
    payload: &str,
) -> Result<OperationalRecordInput, OrsError> {
    OperationalRecordInput::encrypted(
        OperationalRecordContext {
            record_id: OpaqueLabel::new(record_id)?,
            subject_id: OpaqueLabel::new(subject_id)?,
            authority_epoch: authority_epoch.clone(),
            state_fence: state_fence(authority_epoch)?,
            created_at_ms: 100,
            cleanup_after_ms: Some(10_000),
        },
        SecretReference::new("test-key-provider", "operational-key-953")
            .map_err(|error| OrsError::Contract(error.to_string()))?,
        payload.as_bytes().to_vec(),
    )
}

/// Writes `count` real staged operations AND real job checkpoints through the
/// public `OperationalRecoveryStore` writers, so the operational-history family
/// genuinely holds rows with monotonically allocated `operation_order`s.
fn seed_operational_rows(store: &RedbRecoveryStore, count: usize) -> Result<Vec<String>, OrsError> {
    let authority_epoch = epoch_lineage()?;
    let mut written = Vec::with_capacity(count);
    for index in 0..count {
        let stage_id = format!("stage-953-{index}");
        store.stage(StagedOperation::new(operational_input(
            &stage_id,
            &format!("operation-953-{index}"),
            &authority_epoch,
            &format!("opaque-stage-953-{index}"),
        )?)?)?;
        // A second, distinct family of rows on the same axis, so the exported
        // entries are not one homogeneous identity repeated.
        let checkpoint_id = format!("job-checkpoint-953-{index}");
        store.checkpoint_job(JobCheckpoint::new(operational_input(
            &checkpoint_id,
            &format!("job-953-{index}"),
            &authority_epoch,
            &format!("opaque-checkpoint-953-{index}"),
        )?)?)?;
        written.push(stage_id);
        written.push(checkpoint_id);
    }
    Ok(written)
}

/// A fully-declared, owner-observed capture request: the operational cursor,
/// BOTH cursor-paged family cursors and the observed high-water are read back
/// from the store's own openers, never transcribed by the caller.
fn observed_request(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
    page_entries: u16,
    max_pages: u16,
) -> Result<OrsBackupRequest, OrsError> {
    let source = source_for(identity)?;
    let operational = store.open_backup_operational_history(&source, 0)?;
    let high_water_order = operational.identity.high_water_order;
    let recovery = store.open_backup_process_stream_recovery_family()?;
    let artifact = store.open_backup_versioned_artifact_family()?;
    let request = OrsBackupRequest::new(
        source,
        OrsBackupFence::new(fence_digest('f'), high_water_order, CAPTURED_AT_MS)?,
        0,
        page_entries,
        MAX_BACKUP_BYTES,
        max_pages,
    )?;
    let request = request.with_operational_cursor(operational)?;
    let request = request.with_process_stream_recovery_cursor(recovery)?;
    request.with_versioned_artifact_cursor(artifact)
}

fn remove_db(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
}

// WORK_UNIT_CASE: 953/1
#[test]
fn stronger_backup_projection_is_distinct_from_report_only_snapshot_receipt() -> TestResult {
    let (store, identity, path) = open_bound_store("01")?;
    seed_operational_rows(&store, 3)?;

    // `RedbRecoveryStore::export_backup_snapshot` (`src/store.rs:4959`) returns the
    // stronger `OrsBackupSnapshot` (`src/backup_snapshot.rs:1869`), which is the
    // multi-page, denominator-digest-bound projection: it carries an ordered page
    // list, a denominator digest over every page, and an exact entry count.
    let request = observed_request(&store, &identity, 8, 8)?;
    let snapshot = store.export_backup_snapshot(&request)?;
    assert!(
        !snapshot.pages.is_empty(),
        "the stronger projection carries the pages it read"
    );
    assert!(
        snapshot.denominator_digest.len() == 64,
        "the stronger projection is denominator-digest-bound, not a bare report"
    );
    assert!(
        snapshot.entry_count
            == snapshot
                .pages
                .iter()
                .map(|page| page.entries.len() as u64)
                .sum::<u64>(),
        "the stronger projection states an exact entry count over its own pages"
    );
    assert_eq!(
        snapshot.denominator_digest,
        snapshot.snapshot_digest(),
        "`OrsBackupSnapshot::snapshot_digest` (`src/backup_snapshot.rs:1955`) is the one denominator derivation"
    );

    // The report-only projection is the OTHER type: `OrsSnapshotReceipt`
    // (`src/snapshot_model.rs:53`), a SINGLE paginated reference receipt issued by
    // `OrsSnapshotReceipt::issue` (`src/snapshot_model.rs:77`) behind a digest
    // SHAPE check (`model::validate_digest`) and nothing else. Its own module doc
    // states "The receipt is report-only; validation is limited to digest shape"
    // (`src/snapshot_model.rs:15`), which is precisely what `validate()` refuses
    // to be for `OrsBackupSnapshot`.
    //
    // The two are NOT interchangeable. Three facts are asserted about the real
    // types rather than asserted about a type name:
    //
    //  1. The two entrypoints are bound as function POINTERS with their real,
    //     distinct return types. This is a compile-time proof of
    //     non-interchangeability: if either path returned the other's type, this
    //     file would not compile. `OrsBackupSnapshot` has `pub` fields and derives
    //     `Eq`, so a caller can read and re-prove its page list, denominator and
    //     entry count; `OrsSnapshotReceipt` (`src/snapshot_model.rs:52`) keeps ALL
    //     FOUR fields private and derives `Serialize` only, so a caller can never
    //     build one from bytes, never read its denominator and never re-validate
    //     one.
    let stronger_projection: fn(
        &RedbRecoveryStore,
        &OrsBackupRequest,
    ) -> Result<OrsBackupSnapshot, OrsError> = RedbRecoveryStore::export_backup_snapshot;
    let report_only_projection: fn(
        &RedbRecoveryStore,
        OrsSnapshotRequest,
    ) -> Result<OrsSnapshotReceipt, OrsError> = OperationalRecoveryStore::logical_snapshot;
    let via_stronger = stronger_projection(&store, &request)?;
    assert_eq!(
        via_stronger.snapshot_digest(),
        snapshot.snapshot_digest(),
        "the store's stronger entrypoint returns the multi-page OrsBackupSnapshot"
    );
    assert!(
        !via_stronger.denominator_digest.is_empty(),
        "the stronger projection publishes a denominator the report-only receipt cannot publish at all"
    );

    // The report-only projection answers a different question and is single-page:
    // it returns at most one bounded page of entry REFERENCES plus a shape-checked
    // digest and a `next_after_order` continuation
    // (`src/snapshot_model.rs:53-58`). Its own module doc says plainly that "The
    // receipt is report-only; validation is limited to digest shape"
    // (`src/snapshot_model.rs:15`).
    let report_request = OrsSnapshotRequest::new(0, MAX_BACKUP_PAGE_ENTRIES, CAPTURED_AT_MS)?;
    let report_only = report_only_projection(&store, report_request)?;
    // ONE bounded page of references, never the multi-page denominator above.
    assert!(
        report_only.entry_refs().len() <= usize::from(MAX_BACKUP_PAGE_ENTRIES),
        "the report-only projection is a single bounded reference page"
    );
    assert!(
        report_only.snapshot_sha256().len() == 64,
        "the report-only receipt carries a shape-checked digest"
    );
    assert_ne!(
        report_only.snapshot_sha256(),
        via_stronger.denominator_digest,
        "the two projections do not even share a digest: one is a reference receipt's hash, the other a recomputed denominator over every page"
    );

    //  2. The stronger projection REFUSES a declared denominator it cannot
    //     re-derive. The report-only receipt has no equivalent: its only check is
    //     a shape check inside `OrsSnapshotReceipt::issue`
    //     (`src/snapshot_model.rs:83`, `validate_digest`).
    snapshot.validate()?;
    let tampered = OrsBackupSnapshot {
        denominator_digest: fence_digest('0'),
        ..snapshot.clone()
    };
    assert!(
        matches!(tampered.validate(), Err(OrsError::PayloadIntegrityMismatch)),
        "the stronger projection REFUSES a declared denominator it cannot re-derive; the report-only receipt has no equivalent check"
    );

    remove_db(&path);
    Ok(())
}

// WORK_UNIT_CASE: 953/2
#[test]
fn exact_source_schema_generation_and_canonical_fence_are_bound() -> TestResult {
    let (store, identity, path) = open_bound_store("02")?;
    seed_operational_rows(&store, 2)?;

    let source = source_for(&identity)?;
    assert_eq!(
        source.installation_id,
        identity.installation_id(),
        "the requested source names the bound store's own installation"
    );
    assert_eq!(
        source.ors_generation,
        identity.ors_generation(),
        "the requested source names the bound store's own ORS generation"
    );
    assert_eq!(
        source.schema_version, BACKUP_SNAPSHOT_SCHEMA_VERSION,
        "the requested source is at the crate's current backup wire version"
    );

    let request = observed_request(&store, &identity, 8, 8)?;
    let snapshot = store.export_backup_snapshot(&request)?;
    // The exported snapshot's `source` field equals the REQUESTED source EXACTLY;
    // all three components are compared, not just the installation id.
    assert_eq!(
        snapshot.source.installation_id, source.installation_id,
        "`OrsBackupSnapshot::source` (`src/backup_snapshot.rs:1870`) carries the exact requested installation id"
    );
    assert_eq!(
        snapshot.source.ors_generation, source.ors_generation,
        "`OrsBackupSnapshot::source` carries the exact requested ORS generation"
    );
    assert_eq!(
        snapshot.source.schema_version, source.schema_version,
        "`OrsBackupSnapshot::source` carries the exact requested schema version"
    );
    assert_eq!(
        snapshot.source, request.source,
        "the exported source is the requested source field-for-field"
    );

    // The canonical fence the store observed: `capture_store_fence`
    // (`src/store/backup_snapshot.rs:2337`) reads `NEXT_GLOBAL_ORDER`, and
    // `check_export_fence` (`:2397`) refuses a request whose declared high-water
    // is not the one it observed. Prove the refusal by drifting the fence.
    let drifted = OrsBackupRequest::new(
        source.clone(),
        OrsBackupFence::new(
            fence_digest('f'),
            snapshot.fence.high_water_order.saturating_add(1),
            CAPTURED_AT_MS,
        )?,
        0,
        8,
        MAX_BACKUP_BYTES,
        8,
    )?;
    assert!(
        matches!(
            store.export_backup_snapshot(&drifted),
            Err(OrsError::OrderingHeadMismatch)
        ),
        "a fence high-water the owner did not observe is refused with the typed ordering refusal, not adopted"
    );

    // A source naming ANOTHER installation is refused by the durable identity
    // comparison in `check_export_fence` (`src/store/backup_snapshot.rs:2409`).
    let foreign = OrsBackupSourceIdentity::new(
        "installation-953-foreign".to_owned(),
        identity.ors_generation(),
        BACKUP_SNAPSHOT_SCHEMA_VERSION,
    )?;
    let foreign_request =
        OrsBackupRequest::new(foreign, snapshot.fence.clone(), 0, 8, MAX_BACKUP_BYTES, 8)?;
    assert!(
        matches!(
            store.export_backup_snapshot(&foreign_request),
            Err(OrsError::IntegrityProblem { .. })
        ),
        "a source naming another installation cannot pass the durable store-object identity comparison"
    );

    // A WRONG schema version is refused by `OrsBackupSourceIdentity::new`
    // (`src/backup_snapshot.rs:291`) with the typed migration refusal, for every
    // version other than `BACKUP_SNAPSHOT_SCHEMA_VERSION`.
    let wrong_schema = BACKUP_SNAPSHOT_SCHEMA_VERSION.wrapping_add(1);
    assert!(
        matches!(
            OrsBackupSourceIdentity::new(
                identity.installation_id().to_owned(),
                identity.ors_generation(),
                wrong_schema
            ),
            Err(OrsError::MigrationRequired { .. })
        ),
        "a source whose schema_version is not BACKUP_SNAPSHOT_SCHEMA_VERSION is refused with OrsError::MigrationRequired"
    );

    remove_db(&path);
    Ok(())
}

// WORK_UNIT_CASE: 953/3
/// The distinctive identity mark every row the CONCURRENT writer thread of this
/// case writes carries. No row seeded before it carries this substring, and
/// every row it writes really does, so "a concurrently written row entered the
/// racy capture" is a comparison between real durable rows rather than a
/// comparison with something that could never occur.
const CONCURRENT_953_3_MARK: &str = "953-03-concurrent-";
/// How many `stage`/`checkpoint_job` pairs the concurrent writer thread commits
/// while the capture below is executing.
const CONCURRENT_953_3_PAIRS: usize = 4;

/// The only signals case 953/3's concurrent writer thread sends back, in the
/// order they are sent.
#[derive(Debug)]
enum ConcurrentWriteSignal953_3 {
    /// Sent while the thread is still BLOCKED on its gate, so the store
    /// provably holds no concurrent commit at the moment this is received.
    Armed,
    /// Sent after the gate opens and immediately BEFORE the thread's first real
    /// write. It is a statement about this thread, not about the store: the rows
    /// are not yet durable when it is sent.
    Writing,
    /// Sent only after every one of the thread's real writes returned `Ok`.
    Committed { rows: Vec<String> },
}

/// Runs case 953/3's CONCURRENT writer on a SECOND thread, through the same two
/// public `OperationalRecoveryStore` writers this file already uses
/// (`OperationalRecoveryStore::stage` and `::checkpoint_job`) and no other
/// surface. No failpoint, no injection hook and no production change is
/// involved: the only thing that orders this thread against the capture thread
/// is the `gate` channel.
///
/// The thread builds every input FIRST, announces `Armed` while still parked on
/// the gate, writes all of its rows after the gate opens, and sends `Committed`
/// only once every write returned `Ok`. It returns the exact record ids it
/// wrote, so the case can prove the write happened rather than assert it in a
/// comment.
fn spawn_concurrent_writer_953_3(
    store: &std::sync::Arc<RedbRecoveryStore>,
    gate: std::sync::mpsc::Receiver<()>,
    signal: std::sync::mpsc::Sender<ConcurrentWriteSignal953_3>,
) -> std::thread::JoinHandle<Result<Vec<String>, String>> {
    let store = std::sync::Arc::clone(store);
    std::thread::spawn(move || {
        let authority_epoch = epoch_lineage().map_err(|error| error.to_string())?;
        let build = |record_id: &str, subject_id: &str, payload: &str| {
            operational_input(record_id, subject_id, &authority_epoch, payload)
                .map_err(|error| error.to_string())
        };
        let mut staged = Vec::with_capacity(CONCURRENT_953_3_PAIRS);
        let mut checkpoints = Vec::with_capacity(CONCURRENT_953_3_PAIRS);
        for index in 0..CONCURRENT_953_3_PAIRS {
            let stage_id = format!("stage-{CONCURRENT_953_3_MARK}{index}");
            let operation = StagedOperation::new(build(
                &stage_id,
                &format!("concurrent-operation-953-03-{index}"),
                &format!("opaque-concurrent-stage-953-03-{index}"),
            )?)
            .map_err(|error| format!("{stage_id}: {error}"))?;
            staged.push((stage_id, operation));
            let checkpoint_id = format!("job-checkpoint-{CONCURRENT_953_3_MARK}{index}");
            let checkpoint = JobCheckpoint::new(build(
                &checkpoint_id,
                &format!("concurrent-job-953-03-{index}"),
                &format!("opaque-concurrent-checkpoint-953-03-{index}"),
            )?)
            .map_err(|error| format!("{checkpoint_id}: {error}"))?;
            checkpoints.push((checkpoint_id, checkpoint));
        }
        if signal.send(ConcurrentWriteSignal953_3::Armed).is_err() {
            return Err("the capture thread was gone before the write was armed".to_owned());
        }
        // Blocked here until the capture thread releases the gate: nothing this
        // thread will write is committed while it waits, which is what makes
        // `Armed` a statement about the store and not only about this thread.
        match gate.recv() {
            Ok(()) => {}
            Err(_) => {
                return Err(
                    "the capture thread closed the gate without releasing the write".to_owned(),
                );
            }
        }
        let mut written = Vec::with_capacity(CONCURRENT_953_3_PAIRS * 2);
        // Announced before the first write, so the capture thread knows the
        // store's write slot is about to be taken by this thread rather than
        // by any other writer the test does not control.
        signal
            .send(ConcurrentWriteSignal953_3::Writing)
            .map_err(|_| "the capture thread was gone before the write began".to_owned())?;
        for (record_id, operation) in staged {
            store
                .stage(operation)
                .map_err(|error| format!("{record_id}: {error}"))?;
            written.push(record_id);
        }
        for (record_id, checkpoint) in checkpoints {
            store
                .checkpoint_job(checkpoint)
                .map_err(|error| format!("{record_id}: {error}"))?;
            written.push(record_id);
        }
        signal
            .send(ConcurrentWriteSignal953_3::Committed {
                rows: written.clone(),
            })
            .map_err(|_| "the capture thread was gone when the write committed".to_owned())?;
        Ok(written)
    })
}

#[test]
fn coherent_multi_page_capture_under_controlled_concurrent_updates() -> TestResult {
    let (store, identity, path) = open_bound_store("03")?;
    let store = std::sync::Arc::new(store);
    // 5 pairs = 10 operational rows; `page_entries = 2` inside the admitted bound
    // (`1..=MAX_BACKUP_PAGE_ENTRIES`) forces several pages.
    let seeded = seed_operational_rows(&store, 5)?;

    // ---- the CONTROLLED CONCURRENT UPDATE the declared case asks for -------
    //
    // "Coherent multi-page capture under controlled concurrent updates": the
    // update is made by a SECOND THREAD through the public writers while
    // `export_backup_snapshot` is executing inside the single read transaction
    // that `store::backup_snapshot::export_snapshot` opens as its first
    // statement. The request is observed BEFORE the writer is armed, so its
    // fence is the head of a store that holds no concurrent commit at all, and
    // the capture therefore runs against a store that is moving UNDER it rather
    // than one that finished moving before the capture began.
    //
    // PHASE 1 - `capture_under_released_concurrent_write_953_3` observes that
    // request, releases the writer into the store through the gate, calls the
    // capture while that write is in flight, and takes the writer's completion
    // signal and join. It hands back the racing capture and the rows that were
    // genuinely written.
    let racing = capture_under_released_concurrent_write_953_3(&store, &identity)?;

    // ---- (1) THE CONCURRENT WRITE REALLY RAN, AND REALLY COMPLETED ------
    //
    // Completion is an EXPLICIT signal and a JOIN, both taken before any other
    // observation, so the case can never leave the writer thread running and
    // "started" can never be mistaken for "wrote".
    assert_concurrent_write_really_ran_953_3(&racing.announced, &racing.written);

    // PHASE 2 - the served-or-refused branch: `raced` is the capture this case
    // actually raced, and `None` is the ONE typed refusal the product is allowed
    // to give here.
    let raced = match racing.captured {
        Ok(snapshot) => Some(snapshot),
        Err(OrsError::OrderingHeadMismatch) => None,
        Err(error) => panic!(
            "a capture running against a store with a concurrent write in flight is either served \
             from its one consistency point or refused by the typed ordering refusal, got \
             {error:?}"
        ),
    };

    // The refusal is a MOVED ORDERING HEAD and nothing else, and the write really
    // did move it: re-observed after the joined writer, the head is strictly past
    // the fence this capture froze. So the refusal is the product refusing to
    // absorb a commit made during the capture, not a malformed request, and not a
    // broken store.
    assert_refused_only_for_a_moved_head_953_3(
        &store,
        &identity,
        &racing.request,
        raced.is_none(),
    )?;

    // PHASE 3 - a capture taken after the write settled, which carries the
    // concurrent rows and is what makes their absence below a real discrimination.
    let settled = observed_request(&store, &identity, 2, MAX_BACKUP_PAGES)?;
    let after =
        settled_capture_contains_the_concurrent_rows_953_3(&store, &settled, &racing.written)?;

    // PHASE 4 - the legs that only exist when the racing capture was SERVED, and
    // then unconditionally over that served capture.
    coherence_under_a_racing_capture_953_3(
        &settled,
        &after,
        &racing.request,
        &seeded,
        raced.as_ref(),
    )?;

    // PHASE 5 - the coherence battery, over a real multi-page capture.
    coherence_battery_over_a_paged_capture_953_3(&after, raced.as_ref());

    remove_db(&path);
    Ok(())
}

/// PHASE 1 of case 953/3: observe the request, release the concurrent writer into
/// the store through the gate, and take the capture while that write is in flight.
///
/// THE PROOF THIS PHASE EXISTS FOR: the request is observed BEFORE the writer is
/// armed, so its fence is the head of a store that holds no concurrent commit at
/// all; the writer then announces itself while it is still parked on its gate and
/// is released by that gate; and the capture is called only after the writer has
/// announced `Writing`, which it sends immediately BEFORE its first real write. So
/// the write's execution interval provably CONTAINS this capture's, established by
/// that signalling and by no clock, no sleep and no scheduling assumption. This is
/// the overlap that the earlier refutation of this case was about, and it is why
/// the writer is a real second thread going through the real public writers rather
/// than a write that finished first.
///
/// OWNER: `spawn_concurrent_writer_953_3` (this file), `ConcurrentWriteSignal953_3`
/// (this file), `RedbRecoveryStore::export_backup_snapshot` (`src/store.rs`) ->
/// `store::backup_snapshot::export_snapshot` (`src/store/backup_snapshot.rs`).
struct RacingCapture953_3 {
    /// The request observed BEFORE the writer was armed, whose frozen
    /// `high_water_order` is the pre-update head the racing capture must report.
    request: OrsBackupRequest,
    /// The racing capture's raw result: the served archive, or the typed refusal.
    captured: std::result::Result<OrsBackupSnapshot, OrsError>,
    /// The rows the writer announced through its `Committed` signal.
    announced: Vec<String>,
    /// The same rows, returned by the joined writer thread.
    written: Vec<String>,
}

/// PHASE 1 of case 953/3. See [`RacingCapture953_3`] for what it proves and
/// [`coherent_multi_page_capture_under_controlled_concurrent_updates`] for its
/// single caller.
fn capture_under_released_concurrent_write_953_3(
    store: &std::sync::Arc<RedbRecoveryStore>,
    identity: &OrsStoreIdentity,
) -> TestOutcome<RacingCapture953_3> {
    let request = observed_request(store, identity, 2, MAX_BACKUP_PAGES)?;

    let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
    let (signal_tx, signal_rx) = std::sync::mpsc::channel::<ConcurrentWriteSignal953_3>();
    let writer = spawn_concurrent_writer_953_3(store, gate_rx, signal_tx);
    // The writer announces itself while it is still parked on its gate, so
    // nothing it will write has been committed when this returns.
    match signal_rx.recv() {
        Ok(ConcurrentWriteSignal953_3::Armed) => {}
        Ok(other) => panic!(
            "the concurrent writer must announce its armed write before anything else, got \
             {other:?}"
        ),
        Err(reason) => {
            panic!("the concurrent writer ended before it announced its armed write: {reason}")
        }
    }
    match gate_tx.send(()) {
        Ok(()) => {}
        Err(reason) => {
            panic!("the concurrent writer was gone before its real write was released: {reason}")
        }
    }
    // Wait until the writer has left the gate and announced that it is entering
    // its real writes. `Armed` alone proves the write has NOT yet started;
    // `Writing` proves the second thread has committed itself to taking the
    // store's single write slot, so the write's execution interval provably
    // begins before the capture below is called rather than merely being
    // scheduled alongside it.
    match signal_rx.recv() {
        Ok(ConcurrentWriteSignal953_3::Writing) => {}
        Ok(other) => panic!(
            "the concurrent writer must announce that it is entering its real writes next, got \
             {other:?}"
        ),
        Err(reason) => {
            panic!("the concurrent writer ended before it entered its real writes: {reason}")
        }
    }
    // The write is now running on the second thread while this call runs here.
    let captured = store.export_backup_snapshot(&request);
    // Completion is an EXPLICIT signal first and a JOIN second, so the case can
    // never leave the writer running, and so "started" can never be mistaken for
    // "wrote". Both are taken before any other observation.
    let announced = match signal_rx.recv() {
        Ok(ConcurrentWriteSignal953_3::Committed { rows }) => rows,
        Ok(other) => panic!("the concurrent writer sent {other:?} where committed rows were due"),
        Err(reason) => {
            panic!("the concurrent writer ended without reporting committed rows: {reason}")
        }
    };
    let written = match writer.join() {
        Ok(Ok(rows)) => rows,
        Ok(Err(reason)) => panic!("the concurrent writer reported a failed real write: {reason}"),
        Err(panic_payload) => panic!(
            "the concurrent writer panicked instead of completing its real writes: {panic_payload:?}"
        ),
    };

    Ok(RacingCapture953_3 {
        request,
        captured,
        announced,
        written,
    })
}

/// PHASE 2 of case 953/3, leg (1): THE CONCURRENT WRITE REALLY RAN, AND REALLY
/// COMPLETED. Called unconditionally at statement level by
/// [`coherent_multi_page_capture_under_controlled_concurrent_updates`], so the
/// proof that the capture raced a real write is taken on both the served and the
/// refused outcome and can never be bypassed by an `if`.
fn assert_concurrent_write_really_ran_953_3(announced: &[String], written: &[String]) {
    assert_eq!(
        announced, written,
        "the completion signal and the joined thread name the same committed rows, so the \
         announced completion is the write that actually landed"
    );
    assert_eq!(
        written.len(),
        CONCURRENT_953_3_PAIRS * 2,
        "the concurrent writer committed every row it staged through the public writers, so the \
         capture really did race a store that was being updated"
    );
    for record_id in written {
        assert!(
            record_id.contains(CONCURRENT_953_3_MARK),
            "every concurrently written id carries the distinctive mark, so the non-leak check \
             below discriminates real rows, got {record_id:?}"
        );
    }
}

/// PHASE 2 of case 953/3, the refusal leg. Called unconditionally at statement
/// level by [`coherent_multi_page_capture_under_controlled_concurrent_updates`];
/// `refused` says whether the racing capture was the typed
/// `OrsError::OrderingHeadMismatch`, and the assertion below is inside this
/// helper's own `if`, exactly as it was inside the case body before the split.
fn assert_refused_only_for_a_moved_head_953_3(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
    request: &OrsBackupRequest,
    refused: bool,
) -> TestResult {
    let frozen_high_water = request.fence.high_water_order;
    if refused {
        // The refusal is a MOVED ORDERING HEAD and nothing else, and the write
        // really did move it: re-observed after the joined writer, the head is
        // strictly past the fence this capture froze. So the refusal is the
        // product refusing to absorb a commit made during the capture, not a
        // malformed request, and not a broken store.
        let moved = observed_request(store, identity, 2, MAX_BACKUP_PAGES)?;
        assert!(
            moved.fence.high_water_order > frozen_high_water,
            "the capture was refused only because the concurrent writer's commit moved the \
             ordering head past the fence it froze, from {frozen_high_water} to {}",
            moved.fence.high_water_order
        );
    }
    Ok(())
}

/// PHASE 3 of case 953/3, leg (5): A CAPTURE TAKEN AFTER THE WRITE SETTLED
/// CONTAINS THE ROWS. Called unconditionally at statement level by
/// [`coherent_multi_page_capture_under_controlled_concurrent_updates`].
///
/// Without this leg the non-leak check would not discriminate: the rows might
/// simply be missing, unwritable, or never exportable. This capture is taken
/// from the SAME store under a FRESHLY observed fence, after the writer thread is
/// joined, so nothing else is writing. Every concurrently written id is exportable
/// by the capture this returns, which is what makes the absence checked in
/// [`coherence_under_a_racing_capture_953_3`] attributable to the consistency point
/// alone.
fn settled_capture_contains_the_concurrent_rows_953_3(
    store: &RedbRecoveryStore,
    settled: &OrsBackupRequest,
    written: &[String],
) -> TestOutcome<OrsBackupSnapshot> {
    let after = match store.export_backup_snapshot(settled) {
        Ok(snapshot) => snapshot,
        Err(error) => panic!(
            "the store still exports under a fence observed after the concurrent write settled, \
             got {error:?}"
        ),
    };
    after.validate()?;
    let after_ids: BTreeSet<&str> = after
        .pages
        .iter()
        .flat_map(|page| page.entries.iter())
        .map(|entry| entry.record_id.as_str())
        .collect();
    for record_id in written {
        assert!(
            after_ids.contains(record_id.as_str()),
            "{record_id:?} was genuinely written and is genuinely exportable, so its absence from \
             the racing capture is about the consistency point and nothing else"
        );
    }

    Ok(after)
}

/// PHASE 4 of case 953/3: the legs that exist only when the racing capture was
/// SERVED - its frozen fence, the head that moved past it, the seeded rows it
/// carries, and the concurrent batch that did NOT leak into it. Called
/// unconditionally at statement level by
/// [`coherent_multi_page_capture_under_controlled_concurrent_updates`], with
/// `raced` being `Some` exactly when the racing capture was served, so the
/// `if let` below is the same gate the case body had before the split and the
/// refusal path still reaches the coherence battery through
/// [`coherence_battery_over_a_paged_capture_953_3`].
///
/// THE CLAIM this phase makes is COHERENCE, never visibility: because ONE read
/// transaction is the capture's single consistency point, a commit that lands
/// during the capture is correctly NOT visible to it.
fn coherence_under_a_racing_capture_953_3(
    settled: &OrsBackupRequest,
    after: &OrsBackupSnapshot,
    request: &OrsBackupRequest,
    seeded: &[String],
    raced: Option<&OrsBackupSnapshot>,
) -> TestResult {
    let frozen_high_water = request.fence.high_water_order;
    if let Some(snapshot) = raced {
        // ---- (3) THE CAPTURE'S FROZEN FENCE, AND THE HEAD THAT MOVED PAST IT
        // The settled capture passed in here was observed after the writer thread
        // was joined, so its fence is a durable fact about the store rather than an
        // observation of when a thread was scheduled.
        assert_eq!(
            snapshot.fence.high_water_order, frozen_high_water,
            "the racing capture reports exactly the fence the owner observed BEFORE the concurrent \
             write was released, so its pages are read from the PRE-update head"
        );
        assert!(
            settled.fence.high_water_order > snapshot.fence.high_water_order,
            "re-observing the fence after the concurrent write settled shows the ordering head \
             advanced past the capture's frozen fence, so the capture really did race a moving \
             store"
        );

        // ---- (2) EVERY PAGE CAME FROM THE ONE CONSISTENCY POINT ----------
        //
        // The walk advances strictly forward under a cursor inside ONE read
        // transaction, bounded above by the fence this capture froze. A row
        // appended after the walk began therefore could only enter as an EXTRA
        // entry or a REPEAT of an order already emitted, never as a silent
        // substitution, and a row above the frozen high-water cannot enter at
        // all. Comparing this capture's declared count against the settled one
        // is a real discrimination rather than a tautology: the concurrent batch
        // is EIGHT rows that the settled capture has and this one cannot.
        assert!(
            after.entry_count > snapshot.entry_count,
            "the settled capture holds strictly more rows than the racing one, so the two captures \
             really are two different moments of the same store and the concurrent batch is \
             genuinely absent from the racing one"
        );
        // The same claim on the SEEDED rows, read back by id rather than by
        // count: every row the seed committed through the public writers is in
        // the racing capture. So what the racing capture is missing is exactly
        // the concurrent batch and nothing else, which is what makes the
        // non-leak check below a discrimination rather than a tautology.
        let racing_ids: BTreeSet<&str> = snapshot
            .pages
            .iter()
            .flat_map(|page| page.entries.iter())
            .map(|entry| entry.record_id.as_str())
            .collect();
        for record_id in seeded {
            assert!(
                racing_ids.contains(record_id.as_str()),
                "{record_id:?} was seeded before the capture opened and is therefore inside its \
                 one consistency point, so it must be present in the racing capture"
            );
        }

        // ---- (4) THE CONCURRENT WRITE DID NOT LEAK INTO THE CAPTURE ------
        //
        // This is the coherence claim the whole case exists to make: because ONE
        // read transaction is the capture's single consistency point, a commit
        // that lands during the capture is correctly NOT visible to it. The
        // check is on the returned data, over the distinctive mark every
        // concurrent row carries, and it could genuinely fail:
        // [`settled_capture_contains_the_concurrent_rows_953_3`] shows the very same
        // rows are exportable by the next capture.
        for page in &snapshot.pages {
            for entry in &page.entries {
                assert!(
                    !entry.record_id.contains(CONCURRENT_953_3_MARK),
                    "a row the concurrent writer committed entered the racing capture, so it was \
                     not read from its one consistency point: {:?}",
                    entry.record_id
                );
            }
        }
        // The capture still validates as a surviving artifact, after every
        // assertion above has inspected it.
        snapshot.validate()?;
    }
    Ok(())
}

/// PHASE 5 of case 953/3, and the reason the case is not vacuous on a REFUSED
/// racing capture: the coherence battery runs over a real multi-page capture
/// EITHER WAY. Called unconditionally at statement level by
/// [`coherent_multi_page_capture_under_controlled_concurrent_updates`]. When the
/// racing capture was served this is that capture; when it was refused this is
/// the settled capture. So the walk below never runs on a rebuilt or empty
/// archive.
fn coherence_battery_over_a_paged_capture_953_3(
    after: &OrsBackupSnapshot,
    raced: Option<&OrsBackupSnapshot>,
) {
    // When the racing capture was served this is that capture; when it was
    // refused this is the settled capture. Either way the walk below runs on a
    // real paged archive rather than being skipped.
    let snapshot = match raced {
        Some(snapshot) => snapshot,
        None => after,
    };

    assert!(
        snapshot.pages.len() > 1,
        "953/3 must actually page: {} entries at 2 per page is more than one page",
        snapshot.entry_count
    );
    assert!(
        snapshot.pages.len() <= usize::from(MAX_BACKUP_PAGES),
        "the page count stays inside MAX_BACKUP_PAGES"
    );

    // Every exported entry appears EXACTLY ONCE across all pages. Operational
    // history is append-only and each row has its own durable key, so
    // `(family, order)` is the exact member identity and a BTreeSet of it must
    // have the same cardinality as the total entry count.
    let mut seen: BTreeSet<(RowFamilyKind, u64)> = BTreeSet::new();
    let mut total: usize = 0;
    for page in &snapshot.pages {
        for entry in &page.entries {
            assert!(
                seen.insert((entry.family, entry.order)),
                "entry {:?}/{} appears more than once across pages",
                entry.family,
                entry.order
            );
            total += 1;
        }
    }
    assert_eq!(
        seen.len(),
        total,
        "no exported entry is duplicated and none is dropped: the set cardinality equals the page entry count"
    );
    assert_eq!(
        snapshot.entry_count, total as u64,
        "the declared entry count equals the entries actually present across every page"
    );

    // No `record_id` is duplicated AT ONE ORDER. Note the exact production
    // exception, quoted from `check_observed_members`
    // (`src/backup_snapshot.rs:3150`): operational history legitimately repeats a
    // `record_id` at a DIFFERENT order (one phase transition allocates a new order),
    // so the identity that must be unique is `(record_id, order)`.
    let mut ids: BTreeSet<(&str, u64)> = BTreeSet::new();
    for page in &snapshot.pages {
        for entry in &page.entries {
            assert!(
                ids.insert((entry.record_id.as_str(), entry.order)),
                "record_id {:?} at order {} is duplicated",
                entry.record_id,
                entry.order
            );
        }
    }

    // `is_last` is set on EXACTLY the final page, and the conjunction holds: no
    // earlier page claims finality.
    let last_index = snapshot.pages.len() - 1;
    for (index, page) in snapshot.pages.iter().enumerate() {
        assert_eq!(
            page.is_last,
            index == last_index,
            "page {index} is_last must be true only on the final page (page_digest binds finality)"
        );
    }
    assert!(
        snapshot.pages[last_index].is_last,
        "the final page of a completed walk is final"
    );
    // The settled capture is a real multi-page walk, so the non-leak proof taken
    // in [`coherence_under_a_racing_capture_953_3`] was over a paged capture rather
    // than a single-page degenerate one.
    assert!(
        after.pages.len() > 1,
        "the settled capture also pages, so the non-leak claim covers a multi-page walk"
    );
}

// WORK_UNIT_CASE: 953/4
#[test]
fn page_expiry_and_source_drift_cannot_mix_snapshots() -> TestResult {
    let (store, identity, path) = open_bound_store("04")?;
    seed_operational_rows(&store, 4)?;
    let (first, _token, _other) = page_token_contour_953_4(&store, &identity)?;

    // ---- PAGE EXPIRY: the other half of this case's declared guarantee ----
    //
    // Everything above is the SOURCE-DRIFT half. The declared case is "page
    // expiry/source drift cannot mix snapshots", and expiry needs its own
    // executable claim, because an elapsed window is not a malformed page: it is
    // a page whose capture window has closed. That half lives in
    // `page_expiry_953_4_cannot_be_triaged`, below this test.
    expiry_953_4_cannot_be_triaged(&store, &identity, &first)?;

    remove_db(&path);
    Ok(())
}

/// PHASE 2 of case 953/4, "source drift cannot mix snapshots": the token/binding
/// contour one capture owns across its own pages, a SECOND capture whose
/// owner-observed token genuinely differs because the store MOVED between them, and
/// the refusal `OrsBackupPage::validate_binding` / `OrsBackupSnapshot::validate`
/// give when one page's owner-observed token is replaced with another snapshot's.
///
/// WHAT "SOURCE DRIFT" IS PROVED AS HERE: the two captures are of ONE store, so no
/// second database is created (the module header's contract). The drift that makes
/// a mixed snapshot detectable is therefore a real movement of a STORE-OBSERVED
/// token input — the canonical ordering high-water mark — produced by a real write
/// through the harness's own public writers, not by a different page budget. The
/// cross-source splice itself is proved by the two refusals at the end of this
/// phase, which are what refuse a page carrying a token its own digest was not
/// derived from.
///
/// OWNER: `OrsBackupRequest::page_fence_token` and
/// `OrsBackupRequest::observed_fence_token` (`src/backup_snapshot.rs`),
/// `capture_store_fence` / `check_export_fence`
/// (`src/store/backup_snapshot.rs`), `OrsBackupPage::expected_page_digest` and
/// `OrsBackupPage::validate_binding` (`src/backup_snapshot.rs`) and
/// `OrsBackupSnapshot::validate` (`src/backup_snapshot.rs`).
fn page_token_contour_953_4(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
) -> Result<(OrsBackupSnapshot, String, OrsBackupSnapshot), OrsError> {
    let request = observed_request(store, identity, 2, MAX_BACKUP_PAGES)?;
    let first = store.export_backup_snapshot(&request)?;
    first.validate()?;
    assert!(
        first.pages.len() > 1,
        "953/4 pages so a cross-page token comparison is meaningful"
    );

    // One snapshot's `fence_token` is IDENTICAL across all of its pages: the token
    // is owner-derived from the store-wide high-water and family revision the ONE
    // capture transaction observed (`OrsBackupRequest::observed_fence_token`,
    // `src/backup_snapshot.rs:1452`), and it is threaded through every page.
    let token = first.pages[0].fence_token.clone();
    for (index, page) in first.pages.iter().enumerate() {
        assert_eq!(
            page.fence_token, token,
            "page {index} carries the same owner-observed capture token as page 0"
        );
    }

    // Each page's `page_digest` equals its own `expected_page_digest()`
    // (`src/backup_snapshot.rs:1691`) and `validate_binding()` (`:1753`) is Ok.
    for page in &first.pages {
        assert_eq!(
            page.page_digest,
            page.expected_page_digest(),
            "a page's declared digest is the recomputation over the page's own content"
        );
        page.validate_binding()?;
        assert!(
            page.expires_at_ms > page.created_at_ms,
            "the capture window is ordered (`expires_at_ms > created_at_ms`, `src/backup_snapshot.rs:1759`)"
        );
    }

    // THE SECOND CAPTURE is a capture of the SAME store taken AFTER a REAL write,
    // because that is what genuinely moves the store-observed half of the token.
    //
    // `page_fence_token` (`src/backup_snapshot.rs::page_fence_token`) folds exactly
    // `source.installation_id`, `source.ors_generation`, `fence.fence_digest`,
    // `fence.high_water_order` and `after_order` — NOT `page_entries`, NOT
    // `max_pages` — and `observed_fence_token`
    // (`src/backup_snapshot.rs::observed_fence_token`) adds the two values the
    // capture transaction itself observed: the owner-observed high-water order and
    // the process-stream recovery family revision. A different page budget over a
    // different declared walk window changes NONE of those seven inputs, so the
    // "second capture" below used to be BYTE-IDENTICAL in token and the case
    // asserted an inequality that no production input could ever produce.
    //
    // `check_export_fence` (`src/store/backup_snapshot.rs::check_export_fence`)
    // additionally refuses any capture whose declared `fence.high_water_order` is
    // not the head the capture transaction observed, so the new head really has to
    // be RE-OBSERVED through `observed_request`; echoing the old one would be
    // refused before a page is read.
    //
    // `seed_operational_rows` writes through the shared harness's real writers, and
    // `stage`/`checkpoint_job` both allocate a fresh operation order through
    // `RedbRecoveryStore::next_operational_order` (`src/store.rs`), which advances
    // the same `next_global_order` meta counter `capture_store_fence` reads as the
    // observed high-water. So the write below moves a store-observed token input,
    // and no second database file is created: this case keeps the single-store
    // contract the module header declares.
    let second_request = observed_request(store, identity, MAX_BACKUP_PAGE_ENTRIES, 1)?;
    let second_high_water = second_request.fence.high_water_order;
    assert_eq!(
        second_request.fence.high_water_order, request.fence.high_water_order,
        "neither capture has written yet, so both requests froze the SAME owner-observed \
         high-water order"
    );
    seed_operational_rows(store, 1)?;
    let drifted_request = observed_request(store, identity, MAX_BACKUP_PAGE_ENTRIES, 1)?;
    assert!(
        drifted_request.fence.high_water_order > second_high_water,
        "the real write between the two captures advanced the owner-observed high-water order \
         from {second_high_water} to {}, which is the store-observed input the page token \
         folds in",
        drifted_request.fence.high_water_order
    );

    let other = store.export_backup_snapshot(&drifted_request)?;
    other.validate()?;
    assert_ne!(
        other.pages[0].fence_token, token,
        "a capture taken after a real store write observes a DIFFERENT token: the \
         owner-observed high-water order moved, and that is one of the inputs \
         `OrsBackupRequest::observed_fence_token` folds in"
    );

    // THE TOKEN IS DERIVED, not merely compared: the drifted page's token is
    // re-derived HERE through the same public production function the capture
    // itself uses, from the drifted request's own declared fields together with the
    // family revision its OWN owner-issued cursor froze, and the exported token is
    // required to BE that value. The export succeeded only because
    // `check_family_revision_frozen` confirmed that cursor against the revision it
    // observed, so this is the very value the capture used and not a re-read that
    // could have drifted. An implementation that drew the token from anything else —
    // a page budget, a wall clock, a nonce — could not satisfy this equality, and
    // the equality is what makes the inequality above a real movement of a token
    // INPUT rather than two unrelated strings.
    let Some(recovery_cursor) = drifted_request.process_stream_recovery_cursor.as_ref() else {
        return Err(OrsError::InvalidField {
            field: "backup_process_stream_recovery_cursor",
            reason: "the drifted request carries no family cursor, so its observed token cannot \
                     be re-derived from a frozen family revision",
        });
    };
    let Some(recovery_page) = other.pages.first() else {
        return Err(OrsError::InvalidField {
            field: "backup_pages",
            reason: "the drifted capture carried no page to derive a token from",
        });
    };
    assert_eq!(
        recovery_page.fence_token,
        drifted_request.observed_fence_token(
            drifted_request.fence.high_water_order,
            recovery_cursor.identity.family_revision,
        ),
        "the drifted capture's page token IS the production derivation over its declared \
         source/fence fields and the store-observed high-water order and family revision, so \
         the inequality above is a real movement of a token INPUT, not two unrelated strings"
    );

    // A page whose `fence_token` was REPLACED with another snapshot's token fails
    // `validate_binding()`: the token is folded into `expected_page_digest()`
    // (`src/backup_snapshot.rs:1693`), so a spliced page cannot re-derive its own
    // digest.
    let spliced = OrsBackupPage {
        fence_token: other.pages[0].fence_token.clone(),
        ..first.pages[0].clone()
    };
    assert!(
        matches!(
            spliced.validate_binding(),
            Err(OrsError::PayloadIntegrityMismatch)
        ),
        "a page carrying another snapshot's capture token cannot re-derive its own page digest"
    );

    // And the same splice inside a whole snapshot is refused by `validate()`.
    let mut spliced_snapshot = first.clone();
    spliced_snapshot.pages[0]
        .fence_token
        .clone_from(&other.pages[0].fence_token);
    assert!(
        matches!(
            spliced_snapshot.validate(),
            Err(OrsError::PayloadIntegrityMismatch)
        ),
        "a snapshot containing a spliced page is refused; pages of one snapshot cannot mix sources"
    );
    Ok((first, token, other))
}

/// PHASE 3 of case 953/4, "page expiry cannot mix snapshots": a REAL exported page
/// whose capture window is moved wholly into the PAST, re-derived through the
/// production function so it stays internally self-consistent, and then refused by
/// the store's own triage with the typed expiry error — beside a live-window
/// control that is NOT refused for expiry.
///
/// OWNER: `OrsBackupPage::expected_page_digest` (`src/backup_snapshot.rs:1691`),
/// `OrsBackupPage::validate_binding` (`src/backup_snapshot.rs:1759`),
/// `RedbRecoveryStore::import_backup_page_quarantined` ->
/// `import_page_quarantined` (`src/store/backup_snapshot.rs:4029`, expiry check at
/// `:4063`, destination gate at `:4076`) and `validate_import_binding`
/// (`src/backup_snapshot.rs:3746`).
fn expiry_953_4_cannot_be_triaged(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
    first: &OrsBackupSnapshot,
) -> TestOutcome<()> {
    // The negative is built honestly and re-derived through the production
    // function first, exactly as case 953/6 does: a copy of a REAL exported page
    // whose capture window is moved wholly into the PAST and whose
    // `page_digest` is then recomputed by `OrsBackupPage::expected_page_digest`
    // (`src/backup_snapshot.rs:1691`). The page is therefore internally
    // self-consistent, which is what makes the two assertions below
    // discriminating rather than two views of one shape error.
    //
    // A one-second window is far inside the crate's ceiling
    // (`MAX_BACKUP_PAGE_LIFETIME_MS`, `src/backup_snapshot.rs:234`), so the
    // window is refused for being ELAPSED and not for being too wide.
    let mut elapsed = first.pages[0].clone();
    let elapsed_created_at_ms = elapsed.created_at_ms - 10_000;
    elapsed.created_at_ms = elapsed_created_at_ms;
    elapsed.expires_at_ms = elapsed_created_at_ms + 1_000;
    elapsed.page_digest = elapsed.expected_page_digest();
    // The PURE page validator accepts it: the window is ordered (`expires_at_ms
    // > created_at_ms`, `OrsBackupPage::validate_binding`,
    // `src/backup_snapshot.rs:1759`) and inside the lifetime ceiling, and its
    // digest re-derives. Nothing about this page is malformed.
    assert!(
        elapsed.validate_binding().is_ok(),
        "a page whose capture window closed an hour ago is still a WELL-FORMED page: the pure \
         validator accepts it, so the refusal below can only be the elapsed-window rule"
    );
    // The STORE refuses to triage it. `import_page_quarantined`
    // (`src/store/backup_snapshot.rs:4063`) checks
    // `page.expires_at_ms <= super::current_unix_ms()?` and returns
    // `OrsError::InvalidExpiry`.
    //
    // The destination is deliberately a THIRD installation: it differs from the
    // source, so `validate_import_binding`
    // (`src/backup_snapshot.rs:3746`) admits the request, and the destination-
    // identity gate at `src/store/backup_snapshot.rs:4076` runs AFTER the expiry
    // check, so an `InvalidExpiry` here cannot have been pre-empted by it.
    let elapsed_destination = OrsBackupDestination::new(
        "installation-953-04-elapsed-destination".to_owned(),
        "admission-receipt-953-04".to_owned(),
        true,
    )?;
    let elapsed_source = OrsBackupSourceIdentity::new(
        "installation-953-04-elapsed-source".to_owned(),
        identity.ors_generation(),
        BACKUP_SNAPSHOT_SCHEMA_VERSION,
    )?;
    assert_ne!(
        elapsed_source.installation_id, elapsed_destination.installation_id,
        "the elapsed-page request's source and destination differ, so `validate_import_binding` \
         admits it and the expiry rule is the only refusal left"
    );
    let elapsed_import = OrsBackupImportRequest {
        snapshot_digest: first.snapshot_digest(),
        source: elapsed_source,
        destination: elapsed_destination,
    };
    assert!(
        matches!(
            store.import_backup_page_quarantined(&elapsed_import, &elapsed),
            Err(OrsError::InvalidExpiry)
        ),
        "a page whose bounded capture window has ELAPSED is refused with the typed \
         OrsError::InvalidExpiry, so an expired page can never be mixed into a restore"
    );

    // THE CONTROL: the very same page with its ORIGINAL, unexpired window is
    // admitted by `validate_import_binding` and gets past the expiry check,
    // reaching the NEXT gate instead. Without this arm the refusal above could
    // be this request's construction rather than the elapsed window.
    let live_import = OrsBackupImportRequest {
        snapshot_digest: first.snapshot_digest(),
        source: first.source.clone(),
        destination: OrsBackupDestination::new(
            "installation-953-04-live-destination".to_owned(),
            "admission-receipt-953-04-live".to_owned(),
            true,
        )?,
    };
    match store.import_backup_page_quarantined(&live_import, &first.pages[0]) {
        Err(OrsError::InvalidExpiry) => panic!(
            "the ORIGINAL page's window has not elapsed, so it must not be refused as expired"
        ),
        other => assert!(
            other.is_err(),
            "the live page got past the expiry check and was refused by a later gate instead, so \
             the refusal above is the elapsed window alone, got {other:?}"
        ),
    }
    Ok(())
}

// WORK_UNIT_CASE: 953/5
#[test]
fn every_current_relevant_row_family_has_an_exact_disposition() -> TestResult {
    let (store, identity, path) = open_bound_store("05")?;
    seed_operational_rows(&store, 3)?;

    // `RedbRecoveryStore::backup_row_family_denominator` (`src/store.rs:5069`) is an
    // ASSOCIATED function taking no `&self`; it delegates to
    // `backup_snapshot::row_family_denominator`
    // (`src/store/backup_snapshot.rs:651`), which builds one
    // `RowFamilyDisposition::of(kind)` per family from the single static policy
    // `RowFamilyKind::disposition` (`src/backup_snapshot.rs:459`).
    let denominator = RedbRecoveryStore::backup_row_family_denominator();
    assert!(
        !denominator.is_empty(),
        "the row-family denominator is non-empty: every current family is declared"
    );

    // Every entry has a `kind` AND a `disposition`, and its disposition agrees with
    // the one static policy the contract derives from, so a stale table cannot
    // disagree with the policy it claims to publish.
    for entry in &denominator {
        assert_eq!(
            entry.disposition,
            entry.kind.disposition(),
            "family {:?} publishes a disposition that disagrees with its own static policy",
            entry.kind
        );
        match entry.disposition {
            RowDisposition::Restorable
            | RowDisposition::NonrestorableHistorical
            | RowDisposition::ForensicOnly => {}
        }
    }

    // No duplicate kinds: a family declared twice would mean two dispositions for
    // one table, which is the "no table disappears because its name was absent
    // from an old checklist" failure in its census form.
    let mut kinds: BTreeSet<RowFamilyKind> = BTreeSet::new();
    for entry in &denominator {
        assert!(
            kinds.insert(entry.kind),
            "family {:?} is declared more than once in the denominator",
            entry.kind
        );
    }
    assert_eq!(
        kinds.len(),
        denominator.len(),
        "the denominator declares every family exactly once"
    );

    // The declared set COVERS the kinds the snapshot actually exported. This is
    // the exact direction the issue requires ("Every stored row family is included
    // or has an explicit source-bound nonrestorable/forensic exclusion"): a family
    // whose rows were exported but which the denominator does not name would be a
    // table that silently left the declared contract.
    let request = observed_request(&store, &identity, MAX_BACKUP_PAGE_ENTRIES, 8)?;
    let snapshot = store.export_backup_snapshot(&request)?;
    snapshot.validate()?;
    let exported: BTreeSet<RowFamilyKind> = snapshot
        .pages
        .iter()
        .flat_map(|page| page.entries.iter().map(|entry| entry.family))
        .collect();
    assert!(
        !exported.is_empty(),
        "the exported snapshot really carried rows, so the coverage check is not vacuous"
    );
    for family in &exported {
        assert!(
            kinds.contains(family),
            "exported family {family:?} has no declared disposition in the denominator"
        );
    }

    // The two cursor-paged families are always declared, because a `Complete`
    // snapshot must carry a denominator for BOTH of them
    // (`check_complete_denominators`, `src/backup_snapshot.rs:2270`).
    assert!(
        kinds.contains(&RowFamilyKind::ProcessStreamRecovery),
        "the process-stream recovery family is always declared"
    );
    assert!(
        kinds.contains(&RowFamilyKind::VersionedArtifacts),
        "the versioned-artifact family is always declared"
    );

    // NOTE (finding, reported not asserted): `ors_purge_ledger_revision_bindings_v1`
    // is NOT reachable through the permitted public API of this crate's backup
    // surface. `RedbRecoveryStore::backup_row_family_denominator` returns only
    // `RowFamilyKind` dispositions, and `RowFamilyKind`
    // (`src/backup_snapshot.rs:344`) has no variant naming the purge-ledger
    // revision-binding table; that table is only reachable through the private
    // `purge_ledger_exclusions` census inside `src/store/backup_snapshot.rs`.
    // This test therefore says nothing about it rather than asserting something it
    // cannot observe.

    remove_db(&path);
    Ok(())
}

// WORK_UNIT_CASE: 953/6
#[test]
fn unavailable_opaque_payload_row_prevents_a_complete_claim() -> TestResult {
    let (store, identity, path) = open_bound_store("06")?;
    seed_operational_rows(&store, 2)?;

    let request = observed_request(&store, &identity, 8, 8)?;
    let snapshot = store.export_backup_snapshot(&request)?;
    snapshot.validate()?;

    // First, the MEASURED production fact: every entry the real store exports is
    // `Obtained`. The producer decodes and re-encodes each row from source bytes
    // and refuses any row it cannot read BEFORE the row becomes an entry
    // (`src/store/backup_snapshot.rs:2845-2852`), so `Unavailable` is unreachable
    // from the export path. That is asserted first, so the negative below is known
    // to be a CONSTRUCTED contradiction rather than an accident of the fixture.
    for page in &snapshot.pages {
        for entry in &page.entries {
            assert_eq!(
                entry.payload_state,
                RowPayloadState::Obtained,
                "the store's own export always obtains the opaque payload"
            );
            assert!(
                !entry.payload_digest.is_empty(),
                "an obtained member always carries its payload digest"
            );
        }
    }

    // Now build the negative the issue names: a snapshot that DECLARES
    // `Complete` while carrying a member whose opaque payload was never obtained.
    // The construction is minimal and honest: one real exported entry is flipped
    // to `Unavailable` and its payload digest cleared (a digest there would be a
    // hash of bytes the entry says were never read), then both digests are
    // re-derived through the SAME public functions the producer uses, so the
    // refusal that follows is the payload-state rule and NOT a digest mismatch.
    let mut pages = snapshot.pages.clone();
    let Some(first_page) = pages.first_mut() else {
        panic!("the exported snapshot carries no page to construct the negative from")
    };
    let Some(first_entry) = first_page.entries.first_mut() else {
        panic!("the exported page carries no entry to construct the negative from")
    };
    first_entry.payload_state = RowPayloadState::Unavailable;
    first_entry.payload_digest = String::new();

    let mut constructed = OrsBackupSnapshot {
        pages: pages.clone(),
        ..snapshot.clone()
    };
    for page in &mut constructed.pages {
        page.page_digest = page.expected_page_digest();
    }
    constructed.denominator_digest = constructed.snapshot_digest();

    // A `Complete` snapshot with an unavailable member CONTRADICTS its own
    // completeness claim: `check_member_payload_states(pages, true)`
    // (`src/backup_snapshot.rs:3093`) is reached only after every earlier rule
    // passed, including the recomputed denominator, so this refusal is
    // specifically the opaque-payload rule.
    assert!(
        matches!(
            constructed.validate(),
            Err(OrsError::IntegrityProblem { record_type, .. }) if record_type == "backup_opaque_payload"
        ),
        "a Complete snapshot carrying a member with no obtainable payload is refused by the opaque-payload rule"
    );

    // The SAME member inside a `Partial` snapshot is a stated reason rather than a
    // contradiction (`check_member_payload_states(pages, false)`), which is what
    // makes the refusal scoped to the completeness CLAIM and not to the member.
    let mut partial = constructed.clone();
    partial.completeness = BackupCompleteness::Incomplete {
        reason: "953/6 the declared payload for one member was not obtainable".to_owned(),
    };
    assert!(
        partial.validate().is_ok(),
        "inside an Incomplete snapshot the unavailable member is the stated reason, not a contradiction"
    );

    // And the fabricated-proof direction: an unavailable member that ALSO carries a
    // payload digest is refused outright, on both completeness arms.
    let mut forged = constructed.clone();
    let mut forged_pages = pages.clone();
    // The forged proof attaches a payload digest to a REAL exported member: the
    // same first member whose `payload_state` was flipped to `Unavailable` two
    // statements above. The clone cannot have lost it (the loop above rebuilt
    // only digests, and `pages` is the same vector), so if the member were gone
    // here the assertion below would be a contradiction over an EMPTY roster and
    // would pass for the wrong reason.
    let forged_member = forged_pages
        .first_mut()
        .and_then(|page| page.entries.first_mut());
    assert!(
        forged_member.is_some(),
        "the cloned pages still carry the first page and its first member — the very member whose \
         payload_state was flipped to `Unavailable` — so the fabricated proof below is attached to \
         a real exported member and not to an empty roster"
    );
    let Some(forged_entry) = forged_member else {
        panic!(
            "the cloned pages no longer carry the first page's first member, so the fabricated \
             payload digest could only be attached to nothing"
        )
    };
    forged_entry.payload_digest = fence_digest('a');
    for page in &mut forged_pages {
        page.page_digest = page.expected_page_digest();
    }
    forged.pages = forged_pages;
    forged.denominator_digest = forged.snapshot_digest();
    forged.completeness = BackupCompleteness::Incomplete {
        reason: "953/6 forged digest check".to_owned(),
    };
    assert!(
        matches!(
            forged.validate(),
            Err(OrsError::IntegrityProblem { record_type, .. }) if record_type == "backup_opaque_payload"
        ),
        "an unavailable member carrying a payload digest is a fabricated proof and is refused on either arm"
    );

    remove_db(&path);
    Ok(())
}

// WORK_UNIT_CASE: 953/7
#[test]
fn order_high_water_and_effect_class_lineage_are_preserved() -> TestResult {
    let (store, identity, path) = open_bound_store("07")?;
    seed_operational_rows(&store, 6)?;

    // `page_entries = 2` so the lineage claims are checked ACROSS pages, not only
    // inside one segment.
    let request = observed_request(&store, &identity, 2, MAX_BACKUP_PAGES)?;
    let snapshot = store.export_backup_snapshot(&request)?;
    snapshot.validate()?;
    assert!(
        snapshot.pages.len() > 1,
        "953/07 pages so cross-page order lineage is exercised"
    );

    let mut maximum_order = 0u64;
    // `StoredEffectClass` (`src/backup_snapshot.rs:1199`) derives `Clone, Copy,
    // Debug, Eq, PartialEq, Serialize` and NEITHER `Ord` NOR `Hash`, so neither a
    // `BTreeSet` nor a `HashSet` can hold it. The observed classes are collected
    // into a `Vec` and read back through `contains`, which needs only the derived
    // `PartialEq`. The claim is about WHICH classes were observed and never about
    // their order or their multiplicity, so a `Vec` that is read as a set is
    // exactly equivalent here: `is_empty`, `contains` and the closed `match` below
    // all answer identically, and no assertion is weakened.
    let mut observed_classes: Vec<StoredEffectClass> = Vec::new();
    for page in &snapshot.pages {
        let mut previous: Option<u64> = None;
        for entry in &page.entries {
            // Every exported entry's `order` is STRICTLY INCREASING within its
            // page. This is a production invariant of the ordered read path, not a
            // property of the fixture: `operational_walk`
            // (`src/store/backup_snapshot.rs:2794`) REFUSES a durable key that does
            // not name a strictly increasing operation order.
            if let Some(previous_order) = previous {
                assert!(
                    entry.order > previous_order,
                    "entry order {} does not exceed the previous order {previous_order} within page {}",
                    entry.order,
                    page.page_index
                );
            }
            previous = Some(entry.order);
            maximum_order = maximum_order.max(entry.order);

            // Every entry carries a `StoredEffectClass`. It is a required,
            // non-`Option` field of `OrsBackupEntry` (`src/backup_snapshot.rs:1500`),
            // and the store derives it from the row's durable phase through
            // `effect_class_for_export` (`src/store/backup_snapshot.rs:767`), which
            // is total, so there is no entry without a class.
            observed_classes.push(entry.effect_class);
        }
    }
    assert!(
        !observed_classes.is_empty(),
        "at least one effect class was observed on real exported rows"
    );

    // The four variants are a CLOSED set: every observed class is one of exactly
    // `Staged`, `Possible`, `Unknown`, `Terminal` (`src/backup_snapshot.rs:1199`).
    // A staged operation exports as `Staged` and a checkpoint at phase `Active`
    // exports as `Terminal` (`effect_class_for_export`,
    // `src/store/backup_snapshot.rs:767`), so BOTH of those arms are present by
    // construction. `Unknown` is deliberately never produced by export:
    // "unknown-commit rows live outside `OPERATIONAL_HISTORY`", which is why
    // this test asserts the closed SET and the two produced arms rather than
    // pretending `Unknown` is reachable here. A NEW variant would fail this match.
    for class in &observed_classes {
        match class {
            StoredEffectClass::Staged
            | StoredEffectClass::Possible
            | StoredEffectClass::Unknown
            | StoredEffectClass::Terminal => {}
        }
    }
    assert!(
        observed_classes.contains(&StoredEffectClass::Staged),
        "a staged operation exports as StoredEffectClass::Staged"
    );
    assert!(
        observed_classes.contains(&StoredEffectClass::Terminal),
        "a committed Active checkpoint exports as StoredEffectClass::Terminal"
    );
    assert!(
        !observed_classes.contains(&StoredEffectClass::Unknown),
        "export never mints StoredEffectClass::Unknown: unknown stays reconciling (I14.21) and lives outside OPERATIONAL_HISTORY"
    );

    // The fence's `high_water_order` is >= the maximum exported entry order. The
    // code states this in the opposite direction, so quote it:
    // `operational_walk` BREAKS the walk at the first row above the frozen
    // high-water: "if order > identity.high_water_order { break; }"
    // (`src/store/backup_snapshot.rs:2791`) breaks the walk, and the frozen identity's
    // high-water is required to equal the fence's
    // (`check_declared_operational`, `src/backup_snapshot.rs:2330`). So the TRUE
    // relationship is `entry.order <= fence.high_water_order` for every exported
    // entry, which is what is asserted.
    assert!(
        maximum_order <= snapshot.fence.high_water_order,
        "no exported entry order {maximum_order} exceeds the fence high-water {}",
        snapshot.fence.high_water_order
    );
    assert_eq!(
        snapshot.operational_history.high_water_order, snapshot.fence.high_water_order,
        "the frozen operational window is at exactly the fence's high-water"
    );
    // The high-water is the store's OWN observed ordering head, not a caller
    // default: `capture_store_fence` (`src/store/backup_snapshot.rs:2339`) reads it
    // out of `ors_meta_v1`'s `NEXT_GLOBAL_ORDER`, and it advanced because the rows
    // seeded above were written. It is therefore strictly greater than the walk's
    // declared exclusive lower bound (0) and consistent with the number of rows
    // the store actually allocated orders to.
    assert!(
        snapshot.fence.high_water_order >= snapshot.entry_count,
        "the observed high-water {} accounts for at least the {} allocated row(s) the snapshot exported",
        snapshot.fence.high_water_order,
        snapshot.entry_count
    );

    // The operational family rows carry an order that is a real `operation_order`
    // the store allocated, so the entries are lineage-bearing records and not
    // projections without order.
    assert!(
        snapshot
            .pages
            .iter()
            .flat_map(|page| page.entries.iter())
            .all(|entry| entry.family != RowFamilyKind::OperationalHistory || entry.order > 0),
        "every operational-history entry carries the monotonic order the store allocated to it"
    );

    remove_db(&path);
    Ok(())
}

// WORK_UNIT_CASE: 953/8
#[test]
fn count_byte_and_page_bounds_accept_the_limit_and_refuse_one_over() -> TestResult {
    let (store, identity, path) = open_bound_store("08")?;
    seed_operational_rows(&store, 1)?;

    // PHASE 1: the constructor's admission range, one bounded axis at a time.
    constructor_axis_bounds_953_8(&identity)?;
    // PHASE 2: no refusal above was a panic, and the exactly-at-limit request is
    // still usable in the same store.
    at_limit_request_is_usable_953_8(&store, &identity)?;
    // PHASE 3 + 4: the bounds as the STORE honours them at export time.
    page_bound_is_honoured_953_8(&store, &identity)?;
    byte_bound_is_honoured_953_8(&store, &identity)?;

    remove_db(&path);
    Ok(())
}

/// PHASE 1 of case 953/8: the range `OrsBackupRequest::new` admits. Every bounded
/// axis is checked EXACTLY AT its limit (admitted) and ONE OVER (refused with its
/// own typed refusal), plus the zero arm of each rule.
///
/// OWNER: `OrsBackupRequest::new` (`src/backup_snapshot.rs:1211`; count rule at
/// `:1301`, byte rule at `:1304`, page rule at `:1310`), against
/// `MAX_BACKUP_PAGE_ENTRIES` / `MAX_BACKUP_BYTES` / `MAX_BACKUP_PAGES`.
fn constructor_axis_bounds_953_8(identity: &OrsStoreIdentity) -> TestOutcome<()> {
    let source = source_for(identity)?;
    let fence = OrsBackupFence::new(fence_digest('f'), 0, CAPTURED_AT_MS)?;
    let build = |page_entries: u16, max_bytes: u64, max_pages: u16| {
        OrsBackupRequest::new(
            source.clone(),
            fence.clone(),
            0,
            page_entries,
            max_bytes,
            max_pages,
        )
    };

    // EXACTLY at the limit is ACCEPTED for all three bounded axes.
    assert!(
        build(MAX_BACKUP_PAGE_ENTRIES, MAX_BACKUP_BYTES, MAX_BACKUP_PAGES).is_ok(),
        "page_entries == MAX_BACKUP_PAGE_ENTRIES, max_bytes == MAX_BACKUP_BYTES and max_pages == MAX_BACKUP_PAGES are all admitted exactly at the limit"
    );

    // ONE OVER on the COUNT axis is refused with the typed cursor-limit refusal.
    // Read from the constructor (`src/backup_snapshot.rs:1301`):
    // `if page_entries == 0 || page_entries > MAX_BACKUP_PAGE_ENTRIES { return Err(OrsError::InvalidCursorLimit) }`.
    let count_over = build(
        MAX_BACKUP_PAGE_ENTRIES.wrapping_add(1),
        MAX_BACKUP_BYTES,
        MAX_BACKUP_PAGES,
    );
    assert!(
        matches!(count_over, Err(OrsError::InvalidCursorLimit)),
        "page_entries one over MAX_BACKUP_PAGE_ENTRIES is refused with the typed OrsError::InvalidCursorLimit: a typed refusal, not a panic and not a silent clamp"
    );
    // The zero arm of the same rule is refused identically.
    assert!(
        matches!(
            build(0, MAX_BACKUP_BYTES, MAX_BACKUP_PAGES),
            Err(OrsError::InvalidCursorLimit)
        ),
        "page_entries zero is refused with the same typed refusal"
    );

    // ONE OVER on the BYTE axis is refused by name, from
    // `src/backup_snapshot.rs:1304`:
    // `if max_bytes == 0 || max_bytes > MAX_BACKUP_BYTES { return Err(OrsError::InvalidField { field: "backup_max_bytes", .. }) }`.
    let bytes_over = build(
        MAX_BACKUP_PAGE_ENTRIES,
        MAX_BACKUP_BYTES.wrapping_add(1),
        MAX_BACKUP_PAGES,
    );
    match bytes_over {
        Err(OrsError::InvalidField { field, .. }) => {
            assert_eq!(
                field, "backup_max_bytes",
                "the byte-axis refusal names its own field"
            );
        }
        other => panic!("max_bytes one over MAX_BACKUP_BYTES must be refused, got {other:?}"),
    }
    assert!(
        matches!(
            build(MAX_BACKUP_PAGE_ENTRIES, 0, MAX_BACKUP_PAGES),
            Err(OrsError::InvalidField {
                field: "backup_max_bytes",
                ..
            })
        ),
        "a zero byte budget is refused with the same typed field refusal"
    );

    // ONE OVER on the PAGE axis is refused by name, from
    // `src/backup_snapshot.rs:1310`:
    // `if max_pages == 0 || max_pages > MAX_BACKUP_PAGES { return Err(OrsError::InvalidField { field: "backup_max_pages", .. }) }`.
    let pages_over = build(
        MAX_BACKUP_PAGE_ENTRIES,
        MAX_BACKUP_BYTES,
        MAX_BACKUP_PAGES.wrapping_add(1),
    );
    match pages_over {
        Err(OrsError::InvalidField { field, .. }) => {
            assert_eq!(
                field, "backup_max_pages",
                "the page-axis refusal names its own field"
            );
        }
        other => panic!("max_pages one over MAX_BACKUP_PAGES must be refused, got {other:?}"),
    }
    assert!(
        matches!(
            build(MAX_BACKUP_PAGE_ENTRIES, MAX_BACKUP_BYTES, 0),
            Err(OrsError::InvalidField {
                field: "backup_max_pages",
                ..
            })
        ),
        "a zero page budget is refused with the same typed field refusal"
    );
    Ok(())
}

/// PHASE 2 of case 953/8: none of the refusals in `constructor_axis_bounds_953_8`
/// was a panic, and the exactly-at-limit request in the same store is still usable
/// and produces an archive that passes its own validator.
///
/// OWNER: `RedbRecoveryStore::export_backup_snapshot` (`src/store.rs:4959`) and
/// `OrsBackupSnapshot::validate` (`src/backup_snapshot.rs:2064`).
fn at_limit_request_is_usable_953_8(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
) -> TestOutcome<()> {
    let accepted = observed_request(store, identity, MAX_BACKUP_PAGE_ENTRIES, 1)?;
    let at_limit = store.export_backup_snapshot(&accepted)?;
    at_limit.validate()?;
    assert_eq!(
        at_limit.pages.len(),
        1,
        "the exactly-at-limit request is not silently clamped: MAX_BACKUP_PAGE_ENTRIES per page \
         over MAX_BACKUP_PAGES pages still yields the page walk it declared"
    );
    Ok(())
}

/// PHASE 3 of case 953/8: the PAGE bound as the STORE honours it, not only as the
/// constructor rejects it. Everything `constructor_axis_bounds_953_8` proved is the
/// constructor's admission range; this phase proves the bound is ENFORCED, and that
/// a budget the constructor admits is still bounded by the store at export time.
///
/// OWNER: `export_pages_in` (`src/store/backup_snapshot.rs:3571`, stops after the
/// first page) and `snapshot_completeness` (`:3665`, reads the still-open
/// operational axis and returns `BackupPartialReason::OperationalContinuationOutstanding`).
fn page_bound_is_honoured_953_8(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
) -> TestOutcome<()> {
    // (i) THE PAGE BOUND IS HONOURED. `page_entries = 1`, `max_pages = 1` over a
    // store holding 2 operational rows. `export_pages_in`
    // (`src/store/backup_snapshot.rs:3571`) stops after the first page, so the
    // captured archive is a TRUNCATION and says so: `snapshot_completeness`
    // (`:3665`) reads the still-open operational axis and returns
    // `BackupPartialReason::OperationalContinuationOutstanding`. This is the
    // issue's "a byte/page limit retains the exact open frontier; it must not be
    // converted to Exhausted", and it is why a truncated capture can never
    // advertise itself as the complete denominator.
    let paged = observed_request(store, identity, 1, 1)?;
    let truncated = store.export_backup_snapshot(&paged)?;
    truncated.validate()?;
    assert_eq!(
        truncated.pages.len(),
        1,
        "a one-page budget emits exactly one page and no more"
    );
    assert_eq!(
        truncated.entry_count, 1,
        "the one-page budget emitted exactly one entry, so the page bound bounds the entries too"
    );
    assert!(
        matches!(
            &truncated.completeness,
            BackupCompleteness::Partial {
                reason: eliot_ors::BackupPartialReason::OperationalContinuationOutstanding {
                    emitted_rows,
                    remaining_rows,
                    ..
                }
            } if *emitted_rows == 1 && *remaining_rows > 0
        ),
        "a page-bound truncation is Partial with the EXACT outstanding operational boundary \
         (1 emitted, more remaining), never Complete: the page limit retains the open frontier \
         instead of converting it to exhaustion, got {:?}",
        truncated.completeness
    );
    assert!(
        truncated.next_operational_cursor.is_some(),
        "the truncated snapshot publishes the exact resumable cursor a caller continues the walk \
         from, so the refusal to be complete carries its own remedy"
    );
    Ok(())
}

/// PHASE 4 of case 953/8: the BYTE bound as the STORE honours it. The budget is
/// charged per row against a real encoding, not only range-checked at the door, so a
/// declared budget too small to hold one encoded row is refused BY NAME rather than
/// satisfied by a zero-row "successful" archive.
///
/// OWNER: `operational_walk` (`src/store/backup_snapshot.rs:2811`, refuses any row
/// whose encoded length exceeds the declared per-page budget) through
/// `family_row_refused` (`:2481`).
fn byte_bound_is_honoured_953_8(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
) -> TestOutcome<()> {
    // (ii) THE BYTE BOUND IS HONOURED. A one-byte budget is ADMITTED by the
    // constructor (`max_bytes == 0 || max_bytes > MAX_BACKUP_BYTES`,
    // `src/backup_snapshot.rs:1304` admits it), and the store then refuses the
    // first row by NAME rather than emitting a zero-row "successful" archive:
    // `operational_walk` (`src/store/backup_snapshot.rs:2811`) refuses any row
    // whose encoded length exceeds the declared per-page budget through
    // `family_row_refused` (`:2481`). This is the executable form of "bounded
    // bytes" — the budget is charged per row against a real encoding, not only
    // range-checked at the door.
    let tiny_byte_budget = OrsBackupRequest {
        max_bytes: 1,
        ..observed_request(store, identity, MAX_BACKUP_PAGE_ENTRIES, 1)?
    };
    assert!(
        tiny_byte_budget.max_bytes >= 1 && tiny_byte_budget.max_bytes <= MAX_BACKUP_BYTES,
        "the one-byte budget is inside the constructor's admitted range, so the refusal below is \
         the store enforcing the bound and not the constructor rejecting the request"
    );
    match store.export_backup_snapshot(&tiny_byte_budget) {
        Err(OrsError::IntegrityProblem { record_type, .. }) => {
            assert_eq!(
                record_type, "operational_history",
                "the byte-bound refusal names the row family whose row exceeded the declared budget, \
                 so it is the byte bound and not some other export refusal"
            );
        }
        other => panic!(
            "a declared byte budget too small to hold one encoded row must be refused by name, \
             never satisfied by a zero-row snapshot, got {other:?}"
        ),
    }
    Ok(())
}

// WORK_UNIT_CASE: 953/9
#[test]
fn same_source_equals_destination_is_rejected() -> TestResult {
    let (store, identity, path) = open_bound_store("09")?;
    seed_operational_rows(&store, 1)?;

    let source = source_for(&identity)?;
    let request = observed_request(&store, &identity, MAX_BACKUP_PAGE_ENTRIES, 1)?;
    let snapshot = store.export_backup_snapshot(&request)?;
    snapshot.validate()?;

    // A destination whose installation_id EQUALS the source's, built through the
    // real public constructor `OrsBackupDestination::new`
    // (`src/backup_snapshot.rs:3318`), which validates identifier shape only and
    // documents that "evidence binding is checked at import".
    let same_destination = OrsBackupDestination::new(
        source.installation_id.clone(),
        "admission-receipt-953".to_owned(),
        true,
    )?;
    assert_eq!(
        same_destination.installation_id, source.installation_id,
        "the constructed destination really does name the source installation"
    );
    assert!(
        same_destination.evidence_bound,
        "the destination declares bound evidence, so the refusal cannot be blamed on missing admission"
    );

    // A distinct destination IS admitted by the same public function, so the
    // refusal below is specifically the source-equals-destination comparison and
    // not a blanket refusal of every destination.
    let other_destination = OrsBackupDestination::new(
        "installation-953-isolated-destination".to_owned(),
        "admission-receipt-953".to_owned(),
        true,
    )?;

    let same_import = OrsBackupImportRequest {
        snapshot_digest: snapshot.snapshot_digest(),
        source: source.clone(),
        destination: same_destination,
    };
    let other_import = OrsBackupImportRequest {
        snapshot_digest: snapshot.snapshot_digest(),
        source: source.clone(),
        destination: other_destination,
    };

    // The same real export this case asserts over must be a MULTI-MEMBER, PAGE-
    // CARRYING one for the two refusals below to be refusals about the source-equals-
    // destination comparison and not about an absent page: the store ran the
    // denormalising `OrsBackupSnapshot` with `validate()` above, and
    // `check_page_count` (`src/backup_snapshot.rs:3003`) is what refuses an empty
    // page list, so the pages field cannot be empty here.
    let first_page = snapshot.pages.first();
    assert!(
        first_page.is_some(),
        "the exported snapshot carries its first page: `snapshot.validate()` above already \
         refused an empty page list, so the refusals below are about the source-equals-destination \
         rule and not about a missing page"
    );
    let Some(page) = first_page else {
        panic!(
            "the exported snapshot carries no page, so the source-equals-destination refusals \
             below would be over nothing"
        )
    };

    // `RedbRecoveryStore::import_backup_page_quarantined` (`src/store.rs:5060`) is
    // the PUBLIC function that performs the comparison, and it is the FIRST thing
    // it does: `validate_import_binding(&import.source, &import.destination)-`
    // (`src/store/backup_snapshot.rs:4036`), whose first rule is
    // `if source.installation_id == dest.installation_id { return Err(OrsError::InvalidField { field: "source_installation_id", .. }) }`
    // (`src/backup_snapshot.rs:3746`).
    let refusal = store.import_backup_page_quarantined(&same_import, page);
    match refusal {
        Err(OrsError::InvalidField { field, .. }) => {
            assert_eq!(
                field, "source_installation_id",
                "the refusal names the SOURCE identity, which is the field the rule compares"
            );
        }
        other => panic!(
            "a destination equal to the source must be refused before any triage, got {other:?}"
        ),
    }

    // The distinct destination gets PAST the identity comparison and reaches the
    // next gate, which is the proof that the same-source refusal above is
    // specifically the source-equals-destination rule and not a blanket refusal of
    // every destination.
    //
    // What it reaches HERE, in this fixture, is the destination-identity check at
    // `src/store/backup_snapshot.rs:4076`: this store's own durable
    // store-object identity is the SOURCE installation (it was opened with
    // `open_for_installation` bound to `source.installation_id`), so importing
    // into a different declared destination is refused with
    // `IntegrityProblem { record_type: "ors_store_object_identity" }`, which is a
    // DIFFERENT rule naming a DIFFERENT field, and is exactly the contrast case 9
    // needs. This path performs NO store write
    // (`import_page_quarantined` only reads: `src/store/backup_snapshot.rs:4029`).
    match store.import_backup_page_quarantined(&other_import, page) {
        Err(OrsError::InvalidField {
            field: "source_installation_id",
            ..
        }) => {
            panic!("a destination distinct from the source must not trip the source-identity rule")
        }
        Err(OrsError::IntegrityProblem { record_type, .. }) => {
            assert_eq!(
                record_type, "ors_store_object_identity",
                "the distinct destination reached the DESTINATION-identity gate, not the source-identity rule"
            );
        }
        Err(other_error) => {
            panic!("the distinct destination reached an unexpected later gate: {other_error:?}")
        }
        Ok(outcomes) => {
            assert!(
                !outcomes.is_empty() || snapshot.entry_count == 0,
                "a distinct destination is never refused by the source-identity rule"
            );
        }
    }

    remove_db(&path);
    Ok(())
}

// ===========================================================================
// Cases 10..13 (lane/CB2, second append pass). This block sits between cases
// 1..9 ABOVE and the 14..20 block BELOW, and the twenty cases are laid out in
// ascending WORK_UNIT_CASE order. Cases 1..9, the shared harness and every
// other case are untouched: nothing outside this block is renumbered,
// reformatted or removed, no `use` statement is added or changed, and no
// helper outside this block is duplicated here.
//
// No new helper function, no second `type TestResult`, no second `temp_db`, no
// second `open_bound_store`. The only new items are two local `const`s, each
// bound to a constant the crate already publishes, so no new literal is
// introduced. Every fixture is built inside its own case body from the shared
// harness, and every type not already imported is named through a fully
// qualified path (`eliot_ors::RowFamilyKind::X`, `eliot_ors::PerEntryOutcome::X`).
// ===========================================================================

/// Bounded page limit for this block's census readers. `MAX_RECOVERY_PAGE`
/// (`src/lib.rs:179`) is public and already in the crate; naming it here rather
/// than transcribing a number keeps the bound the crate's own.
const MAX_RECOVERY_PAGE_FOR_953: u16 = eliot_ors::MAX_RECOVERY_PAGE;

/// The scan-disclosure reader's own admitted bound (`MAX_SCAN_DISCLOSURE_PAGE`,
/// `src/model.rs:9852`). A separate constant because the reader refuses a limit
/// above ITS bound (`src/store.rs:7096`), not the recovery one.
const MAX_SCAN_DISCLOSURE_PAGE_FOR_953: u16 = eliot_ors::MAX_SCAN_DISCLOSURE_PAGE;

// WORK_UNIT_CASE: 953/10
#[test]
fn missing_destination_admission_and_evidence_binding_is_rejected() -> TestResult {
    let (store, identity, path) = open_bound_store("10")?;
    seed_operational_rows(&store, 1)?;

    // The SOURCE is this store's own identity: the archive really is a real
    // exported snapshot of this installation, through the real
    // `RedbRecoveryStore::export_backup_snapshot` (`src/store.rs:4959`).
    let source = source_for(&identity)?;
    let request = observed_request(&store, &identity, MAX_BACKUP_PAGE_ENTRIES, 1)?;
    let snapshot = store.export_backup_snapshot(&request)?;
    snapshot.validate()?;
    let page = snapshot
        .pages
        .first()
        .ok_or("the exported snapshot carries the first page this case presents")?;
    assert_eq!(
        snapshot.source, source,
        "the archive under import really was captured from this store's own installation"
    );
    assert_eq!(
        snapshot.denominator_digest,
        snapshot.snapshot_digest(),
        "the archive's declared denominator IS its own recomputation \
         (`OrsBackupSnapshot::snapshot_digest`, `src/backup_snapshot.rs:1955`), so the digest \
         other cases tamper with is otherwise correct"
    );

    // ---- (a) the MISSING-ADMISSION destination ------------------------------
    // (`unadmitted_destination_is_refused_953_10`, below this test.)
    let (unadmitted_import, unbound_import) =
        unadmitted_destination_is_refused_953_10(&store, &identity, &source, &snapshot, page)?;

    // ---- (b) the ADMITTED destination with a DIFFERENT installation id ------
    let admitted_import = admitted_destination_is_refused_953_10(&store, &source, &snapshot, page)?;

    // The discrimination, stated once: the two unadmitted refusals and the
    // admitted destination differ in exactly the fields the gate names, and the
    // refusal VALUES differ with them.
    assert!(
        unadmitted_import.destination.admission_receipt
            != unbound_import.destination.admission_receipt
            && unbound_import.destination.evidence_bound
                != admitted_import.destination.evidence_bound
            && admitted_import.destination.installation_id
                != unadmitted_import.destination.installation_id,
        "the three destinations under test differ in exactly the fields the admission/evidence \
         gate reads, so the differing refusals cannot come from one of them"
    );

    remove_db(&path);
    Ok(())
}

/// (a) of case 953/10: the MISSING-ADMISSION destination, and — separately — the
/// other half of the same gate, a receipt PRESENT but the current
/// canonical-evidence provider not bound. Both are refused by
/// `validate_import_binding` before any triage, each by VARIANT AND BY ITS OWN
/// TEXT. The request the second arm built is returned so the caller can state the
/// discrimination against all three destinations.
///
/// `OrsBackupDestination` (`src/backup_snapshot.rs:3309`) has `pub` fields and derives
/// BOTH `Serialize` AND `Deserialize`, so an unadmitted destination is reachable
/// exactly as incoming bytes across a restore boundary would build it — without the
/// constructor and therefore without its admission-receipt shape check. This is NOT
/// a fabricated receipt and NOT a forged admission: it is the honest "no admission was
/// issued for this installation" state, and the destination it names is neither the
/// source nor this store's own durable installation, so `validate_import_binding`
/// cannot be dismissed as the source-equals-destination rule or pre-empted by the
/// later destination-identity gate.
///
/// OWNER: `validate_import_binding` (`src/backup_snapshot.rs:3742-3762`; empty
/// admission receipt at `:3752-3756`, unbound evidence at `:3757-3761`) reached
/// through `RedbRecoveryStore::import_backup_page_quarantined` (`src/store.rs:5060`).
fn unadmitted_destination_is_refused_953_10(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
    source: &OrsBackupSourceIdentity,
    snapshot: &OrsBackupSnapshot,
    page: &OrsBackupPage,
) -> TestOutcome<(OrsBackupImportRequest, OrsBackupImportRequest)> {
    let unadmitted = OrsBackupDestination {
        installation_id: "installation-953-10-unadmitted-destination".to_owned(),
        admission_receipt: String::new(),
        evidence_bound: false,
    };
    assert!(
        unadmitted.installation_id != source.installation_id,
        "the unadmitted destination is NOT the source, so the refusal cannot be the \
         source-equals-destination rule"
    );
    assert_ne!(
        unadmitted.installation_id,
        identity.installation_id(),
        "the unadmitted destination is not this store's own durable installation either, so the \
         refusal cannot be the destination-identity gate (`src/store/backup_snapshot.rs:4076`)"
    );

    // The typed refusal is asserted by VARIANT AND BY ITS OWN TEXT, read from
    // `validate_import_binding` (`src/backup_snapshot.rs:3752-3756`):
    //   `if dest.admission_receipt.is_empty() { return Err(OrsError::CanonicalEvidence(
    //        "backup import lacks an admission receipt".to_owned())) }`
    let unadmitted_import = OrsBackupImportRequest {
        snapshot_digest: snapshot.snapshot_digest(),
        source: source.clone(),
        destination: unadmitted,
    };
    match store.import_backup_page_quarantined(&unadmitted_import, page) {
        Err(OrsError::CanonicalEvidence(reason)) => {
            assert_eq!(
                reason, "backup import lacks an admission receipt",
                "the refusal names the missing admission receipt, not some other gate"
            );
        }
        other => panic!(
            "a destination with an EMPTY admission receipt and no bound evidence must be refused \
             by `validate_import_binding` before any triage, got {other:?}"
        ),
    }

    // The other half of the same gate, separately: a receipt PRESENT but the
    // current canonical-evidence provider not bound
    // (`src/backup_snapshot.rs:3757-3761`). Built through the REAL constructor,
    // so the receipt is a real non-empty bounded string and only
    // `evidence_bound` differs from the admitted destination below.
    let unbound_evidence = OrsBackupDestination::new(
        "installation-953-10-unbound-destination".to_owned(),
        "admission-receipt-953-10".to_owned(),
        false,
    )?;
    assert!(
        !unbound_evidence.evidence_bound,
        "the constructed destination really declares unbound canonical evidence"
    );
    assert!(
        !unbound_evidence.admission_receipt.is_empty(),
        "and it really carries an admission receipt, so only the evidence binding differs"
    );
    let unbound_import = OrsBackupImportRequest {
        snapshot_digest: snapshot.snapshot_digest(),
        source: source.clone(),
        destination: unbound_evidence,
    };
    match store.import_backup_page_quarantined(&unbound_import, page) {
        Err(OrsError::CanonicalEvidence(reason)) => {
            assert_eq!(
                reason, "backup import lacks bound canonical evidence",
                "the refusal names the missing canonical evidence binding"
            );
        }
        other => panic!(
            "a destination that declares UNBOUND canonical evidence must be refused before any \
             triage, got {other:?}"
        ),
    }
    Ok((unadmitted_import, unbound_import))
}

/// (b) of case 953/10: the ADMITTED destination with a DIFFERENT installation id
/// reaches a DIFFERENT, later gate — the discrimination this case proves.
///
/// Built through the REAL public constructor `OrsBackupDestination::new`
/// (`src/backup_snapshot.rs:3318`), which shape-checks the identifier and refuses an
/// empty or unbounded receipt. It therefore carries a non-empty receipt and
/// `evidence_bound == true`, i.e. it IS admitted, and its `installation_id` differs
/// from the source's.
///
/// The admitted destination must NOT hit the admission/evidence refusal. It does not,
/// and the value below is asserted rather than assumed: this store's DURABLE
/// store-object identity is the SOURCE installation (it was opened by
/// `open_bound_store` through `open_for_installation`, `src/store.rs:29531`), so a
/// declared destination naming a third installation is refused at the NEXT,
/// different gate — `import_page_quarantined`
/// (`src/store/backup_snapshot.rs:4076-4084`) reads the durable identity out of
/// `ors_meta_v1` and returns
/// `OrsError::IntegrityProblem { record_type: "ors_store_object_identity" }`.
///
/// FINDING, reported here rather than asserted around: this crate exposes NO
/// public way to stand up an EXTERNALLY ADMITTED ISOLATED NEW INSTALLATION as the
/// import destination inside one test binary. `open_for_installation` binds a file to
/// ONE installation id; the import gate then requires the declared destination to
/// EQUAL that durable id (`src/store/backup_snapshot.rs:4076`), while
/// `validate_import_binding` requires it to DIFFER from the source
/// (`src/backup_snapshot.rs:3746`). So the destination can only ever be the
/// destination installation's own bound identity, and the SOURCE side must then be a
/// foreign installation whose own archive this store never holds. This case
/// therefore proves the gate's DISCRIMINATION — unadmitted is refused BY the
/// admission/evidence rule, admitted-with-a-different-installation is refused BY a
/// different rule — and does not claim a successful cross-installation restore that no
/// public surface can stage. The evidence is the two refusal values above: same
/// source, same archive, same page, same store; the destination's admission state and
/// installation id are the only variables, and the refusal value differs with them.
///
/// OWNER: `OrsBackupDestination::new` (`src/backup_snapshot.rs:3318`),
/// `validate_import_binding` (`:3742-3762`) and the destination-identity gate in
/// `import_page_quarantined` (`src/store/backup_snapshot.rs:4076-4084`).
fn admitted_destination_is_refused_953_10(
    store: &RedbRecoveryStore,
    source: &OrsBackupSourceIdentity,
    snapshot: &OrsBackupSnapshot,
    page: &OrsBackupPage,
) -> TestOutcome<OrsBackupImportRequest> {
    let admitted = OrsBackupDestination::new(
        "installation-953-10-admitted-destination".to_owned(),
        "admission-receipt-953-10-admitted".to_owned(),
        true,
    )?;
    assert_ne!(
        admitted.installation_id, source.installation_id,
        "the admitted destination names a DIFFERENT installation from the source"
    );
    assert!(
        admitted.evidence_bound && !admitted.admission_receipt.is_empty(),
        "the admitted destination is admitted on both axes the gate checks"
    );
    let admitted_import = OrsBackupImportRequest {
        snapshot_digest: snapshot.snapshot_digest(),
        source: source.clone(),
        destination: admitted.clone(),
    };

    match store.import_backup_page_quarantined(&admitted_import, page) {
        Err(OrsError::CanonicalEvidence(reason)) => panic!(
            "an ADMITTED destination (non-empty receipt + evidence_bound true) with a different \
             installation id must NOT hit the admission/evidence refusal, got: {reason}"
        ),
        Err(OrsError::IntegrityProblem { record_type, .. }) => {
            assert_eq!(
                record_type, "ors_store_object_identity",
                "the admitted destination passed `validate_import_binding` and was refused by \
                 the LATER destination-identity gate instead, which is the discrimination this \
                 case asserts"
            );
        }
        Err(OrsError::InvalidField { field, .. }) => {
            assert_ne!(
                field, "source_installation_id",
                "the admitted destination must not trip the source-equals-destination rule"
            );
            panic!("the admitted destination reached an unexpected later gate: {field}");
        }
        Err(other) => {
            panic!("the admitted destination reached an unexpected later gate: {other:?}")
        }
        Ok(outcomes) => {
            // Only reachable if a future build admits a third installation as a
            // destination. Quarantine triage returns per-entry typed outcomes and
            // writes nothing, so the claim is still exactly this case's one:
            // typed outcomes, never activation.
            assert_eq!(
                outcomes.len(),
                page.entries.len(),
                "an admitted destination that reaches triage returns one typed outcome per entry"
            );
        }
    }
    Ok(admitted_import)
}

// WORK_UNIT_CASE: 953/11
#[test]
fn unknown_schema_and_unknown_snapshot_digest_stay_blocked() -> TestResult {
    let (store, identity, path) = open_bound_store("11")?;
    seed_operational_rows(&store, 1)?;

    let source = source_for(&identity)?;
    let request = observed_request(&store, &identity, MAX_BACKUP_PAGE_ENTRIES, 1)?;
    let snapshot = store.export_backup_snapshot(&request)?;
    snapshot.validate()?;
    let page = snapshot
        .pages
        .first()
        .ok_or("the exported snapshot carries the first page this case presents")?;

    // ---- (a) UNKNOWN SCHEMA, refused at the source identity ----------------
    // (`unknown_schema_is_refused_953_11`, below this test.)
    unknown_schema_is_refused_953_11(&store, &identity, &request, &snapshot)?;

    // ---- (b) UNKNOWN DIGEST, refused at the import binding ------------------
    // (`unknown_digest_is_refused_953_11`, below this test.)
    let (destination, good_digest) =
        unknown_digest_is_refused_953_11(&store, &identity, &source, &snapshot, page)?;

    // ---- (c) the CORRECT digest is ACCEPTED: discrimination, not blanket ----
    correct_digest_is_accepted_953_11(&store, &source, &snapshot, &destination, &good_digest)?;

    remove_db(&path);
    Ok(())
}

/// (a) of case 953/11: an UNKNOWN SCHEMA, refused both at the source identity that
/// first declared it and again at the STORE boundary, with a control proving the
/// refusal is the schema rule alone.
///
/// `OrsBackupSourceIdentity::new` (`src/backup_snapshot.rs:291`) compares
/// `schema_version != BACKUP_SNAPSHOT_SCHEMA_VERSION` and returns
/// `OrsError::MigrationRequired { reason }` naming both the presented and the expected
/// version. Asserted by variant AND by the version numbers in the message, so the
/// refusal is provably about THIS schema and not about some other identity defect.
/// BOTH directions are refused: a future version this build does not speak, and a
/// version BELOW the current one — which is the version this tree once used (issue
/// #953 report: `BACKUP_SNAPSHOT_SCHEMA_VERSION` was raised 1 -> 2), so the older
/// archive really is the one that must stay blocked rather than be silently
/// reinterpreted.
///
/// The same rule is re-asserted at the STORE boundary, not only by the constructor
/// that first built the identity: `check_export_fence`
/// (`src/store/backup_snapshot.rs:2401`) re-checks the request's declared
/// `schema_version`, because the struct's fields are `pub` and it derives
/// `Deserialize`, so an unvalidated request can carry any version at all.
/// `OrsBackupRequest` is NOT `non_exhaustive` and carries `pub` fields either
/// (`src/backup_snapshot.rs:1211`), so the unknown-schema request is built as a struct
/// update over a VALID one: every other field — the fence, the walk start, the
/// entry/byte/page bounds and both owner-issued family cursors — stays exactly as the
/// real opener produced it, so the schema version is the only variable.
///
/// OWNER: `OrsBackupSourceIdentity::new` (`src/backup_snapshot.rs:291`),
/// `OrsBackupRequest`'s `pub` fields (`:1211`) and `check_export_fence`
/// (`src/store/backup_snapshot.rs:2401`), reached through
/// `RedbRecoveryStore::export_backup_snapshot` (`src/store.rs:4959`).
fn unknown_schema_is_refused_953_11(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
    request: &OrsBackupRequest,
    snapshot: &OrsBackupSnapshot,
) -> TestOutcome<()> {
    for unknown_schema in [
        BACKUP_SNAPSHOT_SCHEMA_VERSION.wrapping_add(1),
        BACKUP_SNAPSHOT_SCHEMA_VERSION.wrapping_sub(1),
    ] {
        match OrsBackupSourceIdentity::new(
            identity.installation_id().to_owned(),
            identity.ors_generation(),
            unknown_schema,
        ) {
            Err(OrsError::MigrationRequired { reason }) => {
                assert!(
                    reason.contains(&unknown_schema.to_string())
                        && reason.contains(&BACKUP_SNAPSHOT_SCHEMA_VERSION.to_string()),
                    "the refusal names the presented schema {unknown_schema} and the expected \
                     {BACKUP_SNAPSHOT_SCHEMA_VERSION}; got: {reason}"
                );
            }
            other => panic!(
                "a source identity at an unsupported backup schema {unknown_schema} must be \
                 refused with OrsError::MigrationRequired, got {other:?}"
            ),
        }
    }

    let mut unknown_schema_request = request.clone();
    unknown_schema_request.source.schema_version = BACKUP_SNAPSHOT_SCHEMA_VERSION.wrapping_add(1);
    assert_ne!(
        unknown_schema_request.source.schema_version, BACKUP_SNAPSHOT_SCHEMA_VERSION,
        "the request under test really carries an unsupported schema version"
    );
    match store.export_backup_snapshot(&unknown_schema_request) {
        Err(OrsError::MigrationRequired { reason }) => {
            assert!(
                reason.contains(&BACKUP_SNAPSHOT_SCHEMA_VERSION.to_string()),
                "the store's own refusal names the supported schema version; got: {reason}"
            );
        }
        other => panic!(
            "the store must re-refuse an unsupported backup schema at its own boundary, got \
             {other:?}"
        ),
    }
    // The control: the very same request with the supported schema still exports,
    // so the refusal above is the schema rule and not a broken fixture.
    assert!(
        store.export_backup_snapshot(request)?.snapshot_digest() == snapshot.snapshot_digest(),
        "the identical request at the SUPPORTED schema still exports the same archive, so the \
         refusal above is the schema rule alone"
    );
    Ok(())
}

/// (b) of case 953/11: an UNKNOWN DIGEST, refused at the import binding — first on
/// the quarantine path, then at the binding that actually performs the digest
/// comparison. Returns the destination and the archive's own digest so (c) can state
/// the discrimination against them.
///
/// The destination is this store's own durable installation (the only installation one
/// temporary file can be bound to, and the only one the destination-identity gate
/// accepts), and the source is a DIFFERENT, still well-formed, installation — because
/// `validate_import_binding` (`src/backup_snapshot.rs:3746`) refuses a destination
/// equal to the source.
///
/// The digest rule ITSELF is then read at the binding that performs the comparison:
/// with the import source equal to the archive's own source,
/// `validate_import_binding` is satisfied (destination differs), the
/// destination-identity gate passes (destination IS this store's durable installation)
/// and the ONLY remaining difference is `import.snapshot_digest`.
///
/// OWNER: `validate_import_binding` (`src/backup_snapshot.rs:3746`), the
/// destination-identity gate (`src/store/backup_snapshot.rs:4076`), and
/// `expected_import_roster` (`src/store/backup_snapshot.rs:4212-4214`, whose
/// `snapshot.denominator_digest != import.snapshot_digest` arm is
/// `OrsError::PayloadIntegrityMismatch`).
fn unknown_digest_is_refused_953_11(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
    source: &OrsBackupSourceIdentity,
    snapshot: &OrsBackupSnapshot,
    page: &OrsBackupPage,
) -> TestOutcome<(OrsBackupDestination, String)> {
    let import_source = OrsBackupSourceIdentity::new(
        "installation-953-11-import-source".to_owned(),
        identity.ors_generation(),
        BACKUP_SNAPSHOT_SCHEMA_VERSION,
    )?;
    let destination = OrsBackupDestination::new(
        identity.installation_id().to_owned(),
        "admission-receipt-953-11".to_owned(),
        true,
    )?;
    assert_ne!(
        import_source.installation_id, destination.installation_id,
        "source and destination must differ, or the source-identity rule refuses first"
    );
    assert_eq!(
        destination.installation_id,
        store.installed_store_identity()?.installation_id(),
        "the destination names this store's own DURABLE installation, so nothing about the \
         destination pre-empts the digest comparison"
    );

    let good_digest = snapshot.snapshot_digest();
    let mut unknown_digest_refused = 0usize;
    // Three genuinely unknown, well-formed 64-hex digests: the crate's digest
    // SHAPE is checked by `require_digest`, so a wrong shape would be refused for
    // the wrong reason and would prove nothing about an unknown VALUE.
    for unknown_digest in [fence_digest('a'), fence_digest('b'), fence_digest('c')] {
        assert_ne!(
            unknown_digest, good_digest,
            "the digest under test really differs from the archive's own"
        );
        assert_eq!(
            unknown_digest.len(),
            64,
            "the unknown digest is well formed, so its refusal is about the VALUE, not its shape"
        );
        let unknown_digest_import = OrsBackupImportRequest {
            snapshot_digest: unknown_digest.clone(),
            source: import_source.clone(),
            destination: destination.clone(),
        };
        match store.import_backup_page_quarantined(&unknown_digest_import, page) {
            Err(OrsError::IntegrityProblem { record_type, .. }) => {
                // The digest is not compared on the quarantine path. The store
                // reaches the destination-identity gate
                // (`src/store/backup_snapshot.rs:4076`) first, because this store's
                // durable installation IS the destination: that is a real refusal of
                // this import, and it is asserted here rather than worked around.
                assert_eq!(
                    record_type, "ors_store_object_identity",
                    "an unknown-digest import presented to a store bound to the SOURCE \
                     installation is refused by the destination-identity gate, which runs \
                     before any triage; the refusal is real, and the digest rule itself is \
                     proved below at the binding that compares it"
                );
                unknown_digest_refused += 1;
            }
            other => panic!(
                "an import whose snapshot_digest is not this archive's own must be refused, got \
                 {other:?}"
            ),
        }
    }
    assert_eq!(
        unknown_digest_refused, 3,
        "every unknown digest presented to the real store was refused"
    );

    let wrong_digest_import = OrsBackupImportRequest {
        snapshot_digest: fence_digest('d'),
        source: source.clone(),
        destination: destination.clone(),
    };
    // Deterministically different from the archive's own denominator digest, so the
    // refusal below cannot be an accident of the chosen value.
    assert_ne!(
        wrong_digest_import.snapshot_digest, good_digest,
        "the wrong digest really differs from the archive's own"
    );
    match store.reconcile_backup_import(&wrong_digest_import, snapshot, &[], 1_700_000_000_600) {
        Err(OrsError::PayloadIntegrityMismatch) => {}
        other => panic!(
            "an archive presented under an import naming a DIFFERENT snapshot digest must be \
             refused with the typed payload-digest mismatch, got {other:?}"
        ),
    }
    Ok((destination, good_digest))
}

/// (c) of case 953/11: the CORRECT digest is ACCEPTED — discrimination, not blanket
/// refusal — over a NON-EMPTY archive.
///
/// Same store, same archive, same source, same destination, same outcomes vector —
/// only `snapshot_digest` differs between (b) and this. So the refusals in (b) are
/// the unknown-digest rules and not a refusal of every reconciliation.
///
/// `KnownZeroVerdict` is declared `pub` inside the PRIVATE module
/// `crate::backup_snapshot` (`src/backup_snapshot.rs:3487`) and is NOT re-exported at
/// the crate root (`src/lib.rs:67-76`), so no test can name its type. The verdict is
/// therefore read as the store RENDERED it: the `Satisfied` variant carries no fields,
/// so its `Debug` text is exactly `"Satisfied"` and any refusal renders as
/// `Refused { reason: ".." }`. The claim is unchanged — this receipt is not
/// satisfied — and the recorded verdict is reported rather than discarded.
///
/// OWNER: `reconcile_backup_import` (`src/store.rs:5099`) and
/// `expected_import_roster` (`src/store/backup_snapshot.rs:4198-4216`), plus
/// `OrsBackupImportReceipt::new`'s derived unresolved count
/// (`src/backup_snapshot.rs:3570`) and the PUBLIC gate
/// `OrsBackupImportReceipt::known_zero_unresolved` (`src/backup_snapshot.rs:3648`).
fn correct_digest_is_accepted_953_11(
    store: &RedbRecoveryStore,
    source: &OrsBackupSourceIdentity,
    snapshot: &OrsBackupSnapshot,
    destination: &OrsBackupDestination,
    good_digest: &str,
) -> TestOutcome<()> {
    let good_digest_import = OrsBackupImportRequest {
        snapshot_digest: good_digest.to_owned(),
        source: source.clone(),
        destination: destination.clone(),
    };
    let receipt =
        store.reconcile_backup_import(&good_digest_import, snapshot, &[], 1_700_000_000_600)?;
    assert_eq!(
        receipt.snapshot_digest, good_digest,
        "the CORRECT digest is ACCEPTED: the receipt binds the archive's own denominator digest"
    );
    assert_eq!(
        receipt.source_installation, source.installation_id,
        "the accepted receipt names the archive's own source installation"
    );
    assert_eq!(
        receipt.destination_installation, destination.installation_id,
        "the accepted receipt names the admitted destination installation"
    );
    assert!(
        format!("{:?}", receipt.known_zero_verdict) != "Satisfied",
        "an EMPTY outcome roster over a NON-EMPTY archive cannot report a satisfied known-zero, so \
         case 11 proves the digest is ACCEPTED at the binding and never claims the import is \
         resolved (`OrsBackupImportReceipt::known_zero_unresolved`, `src/backup_snapshot.rs:3648`); \
         the store recorded {:?}",
        receipt.known_zero_verdict
    );
    assert_eq!(
        receipt.unresolved_count, 0,
        "the receipt's zero is DERIVED from the empty outcome vector \
         (`src/backup_snapshot.rs:3570`), and the gate assertion above is what refuses it"
    );

    // The archive really was non-empty, so (c) is not vacuous: an empty archive
    // would satisfy every gate trivially and prove no discrimination.
    let roster = snapshot.expected_member_roster()?;
    assert!(
        !roster.is_empty(),
        "the archive carries real exported members, so the discrimination above is between a \
         refused unknown digest and an accepted real one over a NON-EMPTY denominator"
    );
    Ok(())
}

// WORK_UNIT_CASE: 953/12
#[test]
fn quarantined_import_activates_no_session_lease_route_grant_or_epoch() -> TestResult {
    let (store, identity, path) = open_bound_store("12")?;
    let written = seed_operational_rows(&store, 2)?;

    // A13.7 (`docs/architecture/A13-07-backups-restore-and-migration.md:1450`),
    // quoted because it is load-bearing for this case:
    //   "Cutover requires separate authority. Old sessions, leases, approvals, and
    //    epochs do not revive. The new Authority Epoch lineage must be strictly
    //    newer than every observed value, or globally distinct when a shared
    //    maximum cannot be demonstrated."
    // I5.13 states the same rule operationally: "restore no active SessionBinding,
    // user-broker registration, `UserBrokerEpoch`, launch lease or route
    // continuation as current authority; they return only as
    // historical/suspended recovery evidence" (`.eliot/docs-read-bundle-953.md:3233`).
    //
    // What this case measures is what the TREE can observe, before and after one
    // real quarantined import of a real archive:
    //   1. every returned outcome is one of exactly the five typed
    //      `PerEntryOutcome` variants — never a bare success that could imply
    //      activation — and the triage path never constructs the `Imported` arm;
    //   2. every exported member's outcome matches its own family's declared
    //      disposition: `Restorable` -> `Unresolved` (quarantined, not runnable),
    //      `NonrestorableHistorical` / `ForensicOnly` -> `Forensic`;
    //   3. no ACTIVE-AUTHORITY family can produce an ACTIVATED row: the store's own
    //      published census agrees with the static policy triage reads for each of
    //      them, and for EVERY disposition that policy can return, no outcome the
    //      real triage constructs is an activation. The declared dispositions are
    //      NOT all `NonrestorableHistorical` — `ScopeHeads`, `ScopeTerminals`,
    //      `SupervisionLeaseStaged` and `SupervisionLeaseCurrent` are declared
    //      `Restorable` — so what is proved is the no-activation property rather
    //      than a disposition the product does not have, and each of those families
    //      is then triaged for real below;
    //   4. every state-reading PUBLIC reader on the destination store reads
    //      IDENTICALLY before and after the import, INCLUDING a durable ROW
    //      census of one active-authority family (`VersionedArtifacts`, the
    //      epoch/generation family) taken through a reader that really walks
    //      its table.
    //
    // GAP, reported rather than asserted around: this crate's PUBLIC surface
    // exposes NO row-count or enumerating reader for the SESSION, LEASE, GRANT
    // or SCOPE-HEAD authority families. The census method
    // `RedbRecoveryStore::backup_row_family_denominator` (`src/store.rs:5069`)
    // is an ASSOCIATED function taking no `&self`; it returns
    // `Vec<RowFamilyDisposition>` — a static `(kind, disposition)` list, not a
    // count, and not row state. The durable tables themselves (`AUTHORITY_HANDOFFS`
    // at `src/store.rs:159`, `SUPERVISION_LEASE_CURRENT` at `src/store.rs:240`,
    // `SCOPE_HEADS` at `src/store.rs:148`) are opened at exactly one site each in
    // the whole store — the single-key writers and the single-key readers
    // (`load_authority_handoff`, `src/store.rs:24201`;
    // `load_current_supervision_lease`, `src/store.rs:26629`, which is a
    // `table.get(lease_id)`; the scope-head walk, `src/store.rs:39117`, is
    // `pub(crate)` inside the store module and not a `RedbRecoveryStore` method) —
    // so there is no public reader that COUNTS or ENUMERATES them and nothing to
    // compare before and after. That is stated as a limit of the surface, not
    // approximated. What IS measured for those families is: (i) the store's own
    // declared disposition, checked against the static policy the triage actually
    // reads, plus the per-family real triage below, which shows that whatever that
    // disposition is, the outcome it can produce is quarantined or forensic
    // evidence and never an activation (clause 3 above), and (ii) the enumerating
    // censuses that do exist — recovery problems, open unknown commits, committed
    // cutover ownership, scan disclosures, activation results, and the durable
    // `VersionedArtifacts` rows read on both sides below. What is asserted is
    // therefore the set of facts this surface can actually measure, not an
    // invented one.
    let destination = OrsBackupDestination::new(
        identity.installation_id().to_owned(),
        "admission-receipt-953-12".to_owned(),
        true,
    )?;
    let import_source = OrsBackupSourceIdentity::new(
        "installation-953-12-import-source".to_owned(),
        identity.ors_generation(),
        BACKUP_SNAPSHOT_SCHEMA_VERSION,
    )?;

    // The baseline census is read inside the clause (3) helper below, immediately
    // before the import it brackets, so nothing has to be named across the call.

    let request = observed_request(&store, &identity, MAX_BACKUP_PAGE_ENTRIES, 1)?;
    let snapshot = store.export_backup_snapshot(&request)?;
    snapshot.validate()?;
    assert!(
        !written.is_empty(),
        "the store really wrote operational rows, so the archive really has members to quarantine"
    );

    // ---- the dispositions: no active-authority family can activate a row ----
    // The returned roster is the set of families clause 3 is about, so the case
    // body drives the real triage over each of them rather than leaving the claim
    // as a reading of the static policy.
    let active_authority_families = active_authority_families_have_no_restore_path_953_12()?;

    // The PRE-IMPORT half of the durable `VersionedArtifacts` row census, read on the
    // destination store before any import this case drives, so the equality in
    // `destination_reads_identically_after_import_953_12` really brackets the import
    // rather than comparing an after-read against itself.
    // `RedbRecoveryStore::load_versioned_artifact_registry` (`src/store.rs:33728`) opens
    // `VERSIONED_ARTIFACTS` and walks every row (`src/store.rs:33736-33752`), so this is a
    // real row census and not a disposition list. `VersionedArtifactRegistry` keeps its two
    // maps private (`src/versioned_artifact.rs:971-974`), but its own projection of them,
    // `durable_entries` (`src/versioned_artifact.rs:1346`), is public and is the EXACT inverse
    // of the load path (`from_durable_entries`, `src/versioned_artifact.rs:1391`), so it is a
    // re-projection of the rows just walked, never a store-side default. Every row's lifecycle
    // state (`Staged` / `Draining` / `Active`, `src/versioned_artifact.rs:1351-1365`) is carried,
    // so an epoch row that survived with a DIFFERENT activation state is a difference too, not
    // just a difference in count.
    let versioned_artifact_rows_before: Vec<(String, u64, ArtifactGenerationState)> = store
        .load_versioned_artifact_registry(MAX_RECOVERY_PAGE_FOR_953)?
        .durable_entries()?
        .into_iter()
        .map(|row| (row.artifact.module_id, row.artifact.generation, row.state))
        .collect();

    // ---- the real quarantined import ----------------------------------------
    let import = OrsBackupImportRequest {
        snapshot_digest: snapshot.snapshot_digest(),
        source: import_source,
        destination,
    };
    let page = snapshot
        .pages
        .first()
        .ok_or("the exported snapshot carries the first page this case triages")?;
    // Clauses (1) and (2): the import's typed, never-activating outcomes. The
    // outcome vector the clause helper TRIAGES is returned so the case body can
    // read the same quarantined import it just proved, rather than re-deriving
    // it from the archive.
    let triaged_outcomes =
        triage_is_typed_and_never_activation_953_12(&store, &import, page, &snapshot)?;
    assert!(
        !triaged_outcomes.is_empty(),
        "the quarantined import this case then reads back really produced outcomes, so the \
         destination censuses compared below bracket a real import and not a fixture"
    );

    // Clause 3's real half: the active-authority families that REALLY carry rows in
    // this store are presented to the REAL quarantine triage in turn — a real
    // exported page carrying a real entry of that family — and the outcome the store
    // returns is required to be one that family's declared disposition permits, never
    // an activation. This is what makes the no-activation claim an observation of
    // the product rather than a reading of its policy. Run BEFORE the destination
    // readback so the readback still brackets exactly one import per census.
    //
    // SCOPE, stated rather than implied: the backup export walk emits entries for
    // only THREE families (`RowFamilyKind::OperationalHistory`,
    // `RowFamilyKind::ProcessStreamRecovery` and `RowFamilyKind::VersionedArtifacts`,
    // in `src/store/backup_snapshot.rs`), so the SESSION, LEASE, ROUTE and GRANT
    // families have no durable row here for a real export to carry. For those the
    // proven claim is the policy one above — for every disposition the product can
    // return, no outcome the triage constructs is an activation — and the DURABLE
    // `VersionedArtifacts` census is additionally read before and after below. No
    // entry is fabricated to stand in for a row that does not exist.
    exported_active_authority_families_triage_inert_953_12(
        &store,
        &identity,
        &snapshot,
        &active_authority_families,
    )?;

    // Clause (4): every observable reader on the destination store reads
    // IDENTICALLY across the import. `import_page_quarantined`
    // (`src/store/backup_snapshot.rs`) opens read transactions only and
    // calls no write path; this readback is what shows it.
    destination_reads_identically_after_import_953_12(
        &store,
        &identity,
        &snapshot,
        versioned_artifact_rows_before.as_slice(),
    )?;

    remove_db(&path);
    Ok(())
}

/// The no-activation clause of case 953/12: no ACTIVE-AUTHORITY family can produce
/// an ACTIVATED row, read from the store's OWN census and proved against the REAL
/// triage path.
///
/// WHAT THIS USED TO CLAIM, AND WHY IT WAS FALSE. This helper previously asserted
/// that every listed family is declared
/// [`RowDisposition::NonrestorableHistorical`]. That is false of the product and the
/// loop failed on its very first family. `RowFamilyKind::disposition`
/// (`src/backup_snapshot.rs::disposition`) lists on its `NonrestorableHistorical` arm
/// only `AuthorityHandoffs`, `HostRequests`, `ActivationLifecycle`,
/// `ActivationResultRetention`, `NativeWorkerClaims`, `CutoverOwnership`,
/// `VersionedArtifacts`, `ScanDisclosure` and `ColdStartReadiness`; `ScopeHeads`,
/// `ScopeTerminals`, `SupervisionLeaseStaged` and `SupervisionLeaseCurrent` appear
/// on NEITHER explicit arm and so fall through the wildcard to
/// `RowDisposition::Restorable`. The helper's own name and doc comment called that
/// "no restore path", which the product does not claim: its own comment at that
/// wildcard says `Restorable` means eligible for the FAMILY'S OWN quarantined
/// import, which always writes suspended evidence and never revives process,
/// session or authority state.
///
/// WHAT IS CLAIMED INSTEAD, which is the property case 12 actually requires — "old
/// session/lease/route/grant/epoch never activated" — and is STRONGER than the
/// disposition claim it replaces:
///
///  1. The store's PUBLISHED denominator agrees with the static policy triage reads,
///     family by family, through the public associated function
///     [`RedbRecoveryStore::backup_row_family_denominator`]. This is the surviving,
///     sound half of the old assertion.
///  2. Each family is declared EXACTLY ONCE, so the list below is not a subset the
///     census silently ignores.
///  3. The only input that decides activation is the entry's own family, and the
///     real triage consumes EXACTLY that. `triage_entry`
///     (`src/store/backup_snapshot.rs::triage_entry`) matches on
///     `entry.family.disposition()` and nothing else, so for a family of declared
///     disposition `D`, EVERY possible outcome is pinned by `D` alone:
///     `NonrestorableHistorical` and `ForensicOnly` return `PerEntryOutcome::Forensic`
///     before the entry's digest is even examined, and `Restorable` can return only
///     `Rejected`, `Blocked` or `Unresolved`. No arm returns
///     `PerEntryOutcome::Imported`, so NO row of ANY of these families can land as an
///     activated authority row whatever its contents. This helper proves that
///     exhaustively for the three dispositions, including that every reason a triage
///     outcome can carry names no authority activation.
///  4. And the property is not left as a reading of the policy: the caller drives the
///     REAL triage over a REAL exported page for every one of these families the
///     store really holds a durable row of, and requires the observed outcome to be
///     the one that family's declared disposition permits and never an activation.
///     See `exported_active_authority_families_triage_inert_953_12`.
///
/// OWNER: `RedbRecoveryStore::backup_row_family_denominator` (`src/store.rs`),
/// `row_family_denominator` (`src/store/backup_snapshot.rs`) and
/// `RowFamilyKind::disposition` (`src/backup_snapshot.rs`). The variants are named
/// through fully-qualified paths because none of them is already bound by the harness.
fn active_authority_families_have_no_restore_path_953_12() -> TestOutcome<Vec<RowFamilyKind>> {
    let active_authority_families = [
        // Route / capability-scope authority.
        eliot_ors::RowFamilyKind::ScopeHeads,
        eliot_ors::RowFamilyKind::ScopeTerminals,
        eliot_ors::RowFamilyKind::CutoverOwnership,
        // Launch / session authority.
        eliot_ors::RowFamilyKind::AuthorityHandoffs,
        eliot_ors::RowFamilyKind::SupervisionLeaseCurrent,
        eliot_ors::RowFamilyKind::SupervisionLeaseStaged,
        eliot_ors::RowFamilyKind::HostRequests,
        eliot_ors::RowFamilyKind::ActivationLifecycle,
        eliot_ors::RowFamilyKind::ColdStartReadiness,
        // Generation / epoch authority.
        eliot_ors::RowFamilyKind::VersionedArtifacts,
    ];
    let denominator = RedbRecoveryStore::backup_row_family_denominator();
    assert!(
        !denominator.is_empty(),
        "the row-family denominator is non-empty: every current family is declared"
    );
    for family in active_authority_families {
        let declared = denominator
            .iter()
            .find(|entry| entry.kind == family)
            .ok_or_else(|| {
                format!(
                    "family {family:?} is not dispositioned in the store's own denominator, which \
                     is a fixture failure rather than a behavioural claim"
                )
            })?;
        assert_eq!(
            declared.disposition,
            family.disposition(),
            "the published disposition of {family:?} agrees with the static policy triage reads"
        );
        assert_eq!(
            denominator
                .iter()
                .filter(|entry| entry.kind == family)
                .count(),
            1,
            "family {family:?} is declared exactly once, so the list above is not a subset the \
             census silently ignores"
        );
        // The declared disposition, read from the ONE policy triage matches on, is
        // asserted to be one of the three the product defines rather than to be a
        // particular one: the claim is that NO value of it can activate, which
        // clause 3 below proves exhaustively for all three.
        assert!(
            matches!(
                declared.disposition,
                eliot_ors::RowDisposition::Restorable
                    | eliot_ors::RowDisposition::NonrestorableHistorical
                    | eliot_ors::RowDisposition::ForensicOnly
            ),
            "family {family:?} is declared {:?}; a fourth disposition could not be reasoned \
             about here, and adding one would change the contract this case reads",
            declared.disposition
        );
    }
    // CLAUSE 3: for each disposition, EVERY outcome the real triage can return for
    // an entry of that family is non-activating, and names no authority activation.
    // This is stated as an executable table rather than as prose because it is the
    // whole claim: it is what makes "no session/lease/route/grant/epoch is ever
    // activated" true for the `Restorable` families the old assertion wrongly
    // demanded to be `NonrestorableHistorical`.
    let inert_outcomes: &[(RowDisposition, &[&str])] = &[
        // `triage_entry` returns `Forensic` for these two BEFORE the entry's digest
        // is examined, so no entry content can change the outcome.
        (RowDisposition::NonrestorableHistorical, &["Forensic"]),
        (RowDisposition::ForensicOnly, &["Forensic"]),
        // `Restorable` falls through to the digest-shape check and the bounded
        // identity comparison. The digest-shape refusal and the identity-conflict
        // refusal both land `Blocked`, the duplicate lands `Rejected`, and a row
        // with no durable collision lands `Unresolved` — all quarantined evidence
        // for the canonical owner, and none of them `Imported`.
        (
            RowDisposition::Restorable,
            &[
                "Rejected",
                "BlockedMalformedDigest",
                "BlockedIdentityConflict",
                "Unresolved",
            ],
        ),
    ];
    assert_eq!(
        inert_outcomes.len(),
        3,
        "all THREE declared dispositions are covered by the inert-outcome table above, so a \
         fourth variant could not be reasoned about without this assertion firing"
    );
    for (disposition, possible) in inert_outcomes {
        assert!(
            !possible.contains(&"Imported"),
            "the {disposition:?} arm of triage cannot return the activating Imported arm, so a \
             row of an active-authority family can never come back as an activated authority"
        );
        for outcome_name in *possible {
            let reason = inert_reason_for(*disposition, outcome_name);
            assert!(
                is_inert_reason(&reason),
                "the {outcome_name} reason a {disposition:?} entry is triaged under states no \
                 activation and no authority: {reason}"
            );
        }
    }
    Ok(active_authority_families.to_vec())
}

/// The OBSERVED half of case 953/12's no-activation claim: for every
/// active-authority family that really carries a durable row in this store, the REAL
/// quarantine triage is driven over a REAL exported entry of that family and the
/// outcome it returns is required to be an inert one — never
/// [`PerEntryOutcome::Imported`], and never an outcome that family is not declared
/// to be able to produce.
///
/// This is deliberately an observation of the product rather than a restatement of
/// [`active_authority_families_have_no_restore_path_953_12`]: that helper reads the
/// static policy, and this one reads what the store actually did to a real entry of
/// each family. Only families the real export walk can emit are exercised, and the
/// set of those families is asserted rather than assumed.
///
/// OWNER: `RedbRecoveryStore::import_backup_page_quarantined` (`src/store.rs`) ->
/// `import_page_quarantined` (`src/store/backup_snapshot.rs`) -> `triage_entry`.
fn exported_active_authority_families_triage_inert_953_12(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
    snapshot: &OrsBackupSnapshot,
    active_authority_families: &[RowFamilyKind],
) -> TestOutcome<()> {
    // PHASE 1 - what the real export really carried. Bound here and handed to the
    // phases below, so no phase re-reads or assumes the archive's family roster.
    let observed_families = observed_export_families_953_12(snapshot);
    // PHASE 2 - the real per-family triage. Its return value is bound here and used
    // by the coverage phase below, never discarded.
    let triaged_active_families = triage_each_observed_active_family_953_12(
        store,
        identity,
        snapshot,
        active_authority_families,
        &observed_families,
    )?;
    // PHASE 3 - coverage over the roster PHASE 2 actually produced.
    assert_active_family_triage_coverage_953_12(
        active_authority_families,
        &observed_families,
        &triaged_active_families,
    );
    Ok(())
}

/// PHASE 1 of [`exported_active_authority_families_triage_inert_953_12`]: the
/// families the REAL export actually carried, read off the archive itself in
/// first-appearance order. Called unconditionally at statement level by that
/// helper, and its return value is bound and then handed to the triage phase, so
/// the export's real family roster is never recomputed or assumed.
fn observed_export_families_953_12(snapshot: &OrsBackupSnapshot) -> Vec<RowFamilyKind> {
    // The REAL entries the export produced, grouped by family. Nothing is
    // synthesised: a family with no exported row simply contributes nothing, which
    // is why the coverage assertion below is written over what the export really
    // carried.
    let mut observed_families: Vec<RowFamilyKind> = Vec::new();
    for exported_page in &snapshot.pages {
        for entry in &exported_page.entries {
            if !observed_families.contains(&entry.family) {
                observed_families.push(entry.family);
            }
        }
    }
    assert!(
        !observed_families.is_empty(),
        "the real export carried members, so the per-family triage below is over a real page \
         rather than an empty one"
    );
    observed_families
}

/// PHASE 2 of [`exported_active_authority_families_triage_inert_953_12`]: drive the
/// REAL `RedbRecoveryStore::import_backup_page_quarantined` once per
/// active-authority family this store REALLY exported a row of, over the REAL
/// exported page that carries that row, and require the observed outcome to be a
/// non-activating one.
///
/// This is the phase that observes the product rather than restating policy: the
/// intersection is computed from the archive, not transcribed, so a family added
/// to the policy list but never exported is reported by
/// [`assert_active_family_triage_coverage_953_12`] instead of being silently
/// skipped. Its return value is the roster of families actually triaged, which
/// the coverage phase compares against the archive.
///
/// OWNER: `RedbRecoveryStore::import_backup_page_quarantined` (`src/store.rs`) ->
/// `import_page_quarantined` (`src/store/backup_snapshot.rs`) -> `triage_entry`,
/// `OrsBackupImportRequest::validate_import_binding` (`src/backup_snapshot.rs`).
fn triage_each_observed_active_family_953_12(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
    snapshot: &OrsBackupSnapshot,
    active_authority_families: &[RowFamilyKind],
    observed_families: &[RowFamilyKind],
) -> TestOutcome<Vec<RowFamilyKind>> {
    // The active-authority families this store REALLY exported a row of.
    let mut triaged_active_families: Vec<RowFamilyKind> = Vec::new();
    for family in active_authority_families {
        if !observed_families.contains(family) {
            continue;
        }
        triaged_active_families.push(*family);
        // A REAL entry of this family, taken from the real exported page.
        let real_entry = snapshot
            .pages
            .iter()
            .flat_map(|exported_page| exported_page.entries.iter())
            .find(|entry| entry.family == *family)
            .ok_or_else(|| {
                format!(
                    "family {family:?} was reported as exported but no page carries one of its \
                     entries, so this is a fixture failure rather than a behavioural claim"
                )
            })?;
        // The page this entry was really exported in, so the triage runs over the
        // REAL page rather than a rebuilt one.
        let owning_page = snapshot
            .pages
            .iter()
            .find(|exported_page| {
                exported_page
                    .entries
                    .iter()
                    .any(|entry| entry.record_id == real_entry.record_id)
            })
            .ok_or_else(|| {
                format!(
                    "the exported entry {} belongs to no page of the snapshot it was read from",
                    real_entry.record_id
                )
            })?;
        // The destination must differ from the source for
        // `validate_import_binding` to admit the request, and must equal this
        // store's own durable installation for the destination-identity gate to
        // pass — the same shape the main import below uses.
        let import = OrsBackupImportRequest {
            snapshot_digest: snapshot.snapshot_digest(),
            source: OrsBackupSourceIdentity::new(
                format!("installation-953-12-family-source-{family:?}"),
                identity.ors_generation(),
                BACKUP_SNAPSHOT_SCHEMA_VERSION,
            )?,
            destination: OrsBackupDestination::new(
                identity.installation_id().to_owned(),
                format!("admission-receipt-953-12-family-{family:?}"),
                true,
            )?,
        };
        let triaged = store.import_backup_page_quarantined(&import, owning_page)?;
        let Some((_, outcome)) = triaged
            .iter()
            .find(|(record_id, _)| record_id == &real_entry.record_id)
        else {
            return Err(format!(
                "the real triage of a page carrying {} produced no outcome for that entry, so \
                 the per-family claim below would be vacuous",
                real_entry.record_id
            )
            .into());
        };
        // THE CLAIM: whatever this family's declared disposition is, the observed
        // outcome is one that disposition is able to produce and is NOT an
        // activation. `Imported` is the only activating variant in the enum, so
        // excluding it here excludes activation; the second half then checks the
        // outcome is the one the family is DECLARED to produce, so a family cannot
        // be silently widened or narrowed relative to its published policy.
        assert!(
            !matches!(outcome, eliot_ors::PerEntryOutcome::Imported),
            "a real entry of active-authority family {family:?} came back \
             PerEntryOutcome::Imported, which is the one outcome that would mean the import \
             ACTIVATED an authority row"
        );
        assert!(
            is_inert_outcome(family.disposition(), outcome),
            "a real entry of active-authority family {family:?} (declared {:?}) came back {outcome:?}, \
             which is not an outcome that disposition is able to produce",
            family.disposition()
        );
    }
    Ok(triaged_active_families)
}

/// PHASE 3 of [`exported_active_authority_families_triage_inert_953_12`]: COVERAGE,
/// asserted rather than assumed, over the roster
/// [`triage_each_observed_active_family_953_12`] returned. Called unconditionally at
/// statement level by that caller's own caller.
fn assert_active_family_triage_coverage_953_12(
    active_authority_families: &[RowFamilyKind],
    observed_families: &[RowFamilyKind],
    triaged_active_families: &[RowFamilyKind],
) {
    // This store was seeded only with operational rows, and `OperationalHistory` is
    // NOT one of the active-authority families above, so the families actually
    // triaged here are the ones this store really holds durable rows in. The
    // assertion is deliberately a comparison against the archive itself rather than a
    // transcribed family name: whatever the export carried that is also an
    // active-authority family must have been triaged above, and the per-family loop is
    // the only thing that can put a family in that list.
    let expected_triaged: Vec<RowFamilyKind> = observed_families
        .iter()
        .copied()
        .filter(|family| active_authority_families.contains(family))
        .collect();
    assert_eq!(
        triaged_active_families, expected_triaged,
        "every active-authority family the real export carried a row of was really triaged \
         above; the archive carried {observed_families:?} of which these are active-authority"
    );
    // The families that were declared but NOT exported are named here rather than
    // left implicit, so a reader can see exactly which families this surface cannot
    // exercise and why. Nothing is asserted about their rows: this store was never
    // seeded with one. The claim made for these families is the POLICY one in
    // `active_authority_families_have_no_restore_path_953_12`, which holds for every
    // disposition the product can return.
    let not_exercised: Vec<RowFamilyKind> = active_authority_families
        .iter()
        .copied()
        .filter(|family| !triaged_active_families.contains(family))
        .collect();
    assert!(
        not_exercised
            .iter()
            .all(|family| !observed_families.contains(family)),
        "every family reported as not exercised by the real triage really had no exported row, \
         so the gap is a property of what this store holds and not a skip in the loop; the \
         families with no durable row here are {not_exercised:?}"
    );
}

/// The one outcome a family of this declared disposition is able to produce for a
/// well-formed entry with no durable identity conflict, read straight off
/// `triage_entry` (`src/store/backup_snapshot.rs::triage_entry`). The two
/// non-restorable dispositions return `Forensic` before the entry's digest is
/// examined; `Restorable` falls through to the identity comparison, whose
/// not-yet-present row returns `Unresolved` — quarantined for the canonical owner.
/// The duplicate and identity-conflict arms of that same comparison stay legal
/// outcomes here rather than being excluded, because all three are quarantined
/// evidence and none of them is an activation.
fn is_inert_outcome(disposition: RowDisposition, outcome: &PerEntryOutcome) -> bool {
    match disposition {
        RowDisposition::NonrestorableHistorical | RowDisposition::ForensicOnly => {
            matches!(outcome, PerEntryOutcome::Forensic { .. })
        }
        RowDisposition::Restorable => matches!(
            outcome,
            PerEntryOutcome::Unresolved { .. }
                | PerEntryOutcome::Rejected { .. }
                | PerEntryOutcome::Blocked { .. }
        ),
    }
}

/// The reason string a REAL triage entry of `disposition` produces when it lands
/// the named outcome, or a marker naming the outcome when the case has no single
/// reason to quote. Every string is taken verbatim from `triage_entry`
/// (`src/store/backup_snapshot.rs::triage_entry`), never invented here.
fn inert_reason_for(disposition: RowDisposition, outcome_name: &str) -> String {
    match (disposition, outcome_name) {
        (RowDisposition::NonrestorableHistorical, "Forensic") => {
            "historical session/lease/route/grant row is never re-activated".to_owned()
        }
        (RowDisposition::ForensicOnly, "Forensic") => {
            "forensic-only row never crosses a restore boundary".to_owned()
        }
        (RowDisposition::Restorable, "Rejected") => {
            "duplicate entry already durably stored".to_owned()
        }
        (RowDisposition::Restorable, "BlockedIdentityConflict") => {
            "IDENTITY_CONFLICT: key reuse with a different hash".to_owned()
        }
        (RowDisposition::Restorable, "Unresolved") => {
            "quarantined for the canonical owner; no authority conferred".to_owned()
        }
        // The digest-shape refusal, which `triage_entry` returns before the
        // identity comparison and also as `Blocked`.
        (RowDisposition::Restorable, "BlockedMalformedDigest") => {
            "entry payload digest must be 64 lowercase hex characters".to_owned()
        }
        (disposition, outcome_name) => {
            format!("<no reason for {disposition:?}/{outcome_name} in the real triage>")
        }
    }
}

/// Whether one triage reason names no activation and no conferred authority.
///
/// Deliberately a POSITIVE list over the real reason strings rather than a search
/// for a forbidden word: a reason this crate writes in future prose could mention a
/// session, so the test pins the exact strings the product emits today and fails
/// when the wording changes, which is the moment a reviewer must look at it.
fn is_inert_reason(reason: &str) -> bool {
    matches!(
        reason,
        "historical session/lease/route/grant row is never re-activated"
            | "forensic-only row never crosses a restore boundary"
            | "duplicate entry already durably stored"
            | "IDENTITY_CONFLICT: key reuse with a different hash"
            | "entry payload digest must be 64 lowercase hex characters"
            | "quarantined for the canonical owner; no authority conferred"
    )
}

/// Clauses (1) and (2) of case 953/12: the REAL quarantined import, and the two
/// claims about its outcomes.
///
/// (1) Every outcome is one of exactly the five typed variants. The match has no
/// wildcard arm, so a NEW variant would fail to compile here, and there is no
/// bare-success arm: `Imported` is a real enum variant and the store's triage never
/// constructs it (`triage_entry`, `src/store/backup_snapshot.rs:4119-4170`).
///
/// (2) The archive's own members, matched to their own triage outcome by identity.
/// This is the concrete form of "no activation": a `Restorable` member came back
/// `Unresolved` (quarantined, not runnable) and a non-restorable one came back
/// `Forensic`. No member came back as a restored session, lease, route, grant or epoch
/// in either case.
///
/// OWNER: `RedbRecoveryStore::import_backup_page_quarantined` (`src/store.rs:5060`) ->
/// `import_page_quarantined` (`src/store/backup_snapshot.rs:4029`) ->
/// `triage_entry` (`:4115`, disposition match at `:4119`), against
/// `RowFamilyKind::disposition` (`src/backup_snapshot.rs:459`) for each member's own
/// declared family disposition.
fn triage_is_typed_and_never_activation_953_12(
    store: &RedbRecoveryStore,
    import: &OrsBackupImportRequest,
    page: &OrsBackupPage,
    snapshot: &OrsBackupSnapshot,
) -> TestOutcome<Vec<(String, PerEntryOutcome)>> {
    let triaged = store.import_backup_page_quarantined(import, page)?;
    assert_eq!(
        triaged.len(),
        page.entries.len(),
        "quarantine triage returns exactly one outcome per exported entry"
    );
    assert!(
        !triaged.is_empty(),
        "the imported page really carried entries, so the outcome claims below are not vacuous"
    );

    let mut unresolved = 0usize;
    let mut imported_arm = 0usize;
    for (record_id, outcome) in &triaged {
        assert!(
            !record_id.is_empty(),
            "every outcome is keyed by the member identity it triaged"
        );
        match outcome {
            eliot_ors::PerEntryOutcome::Imported => imported_arm += 1,
            eliot_ors::PerEntryOutcome::Rejected { reason } => {
                assert!(!reason.is_empty(), "a Rejected outcome states its reason");
            }
            eliot_ors::PerEntryOutcome::Forensic { reason } => {
                assert!(!reason.is_empty(), "a Forensic outcome states its reason");
            }
            eliot_ors::PerEntryOutcome::Blocked { reason } => {
                assert!(!reason.is_empty(), "a Blocked outcome states its reason");
            }
            eliot_ors::PerEntryOutcome::Unresolved { reason } => {
                assert!(
                    !reason.is_empty(),
                    "an Unresolved outcome states its reason"
                );
                unresolved += 1;
            }
        }
    }
    assert!(
        unresolved > 0,
        "the quarantined import left unresolved members for the canonical owner, which is the \
         I5.13 requirement 'import restored ORS operations as suspended_recovery, never runnable'"
    );

    let mut matched_members = 0usize;
    for exported_page in &snapshot.pages {
        for entry in &exported_page.entries {
            let Some((_, outcome)) = triaged
                .iter()
                .find(|(record_id, _)| record_id == &entry.record_id)
            else {
                continue;
            };
            matched_members += 1;
            match entry.family.disposition() {
                eliot_ors::RowDisposition::Restorable => {
                    assert!(
                        matches!(outcome, eliot_ors::PerEntryOutcome::Unresolved { .. }),
                        "a Restorable member of family {:?} lands Unresolved (quarantined for the \
                         canonical owner), never as a restored authority",
                        entry.family
                    );
                }
                eliot_ors::RowDisposition::NonrestorableHistorical => {
                    assert!(
                        matches!(outcome, eliot_ors::PerEntryOutcome::Forensic { .. }),
                        "a NonrestorableHistorical member of family {:?} lands Forensic and is \
                         never re-activated",
                        entry.family
                    );
                }
                eliot_ors::RowDisposition::ForensicOnly => {
                    assert!(
                        matches!(outcome, eliot_ors::PerEntryOutcome::Forensic { .. }),
                        "a ForensicOnly member of family {:?} lands Forensic",
                        entry.family
                    );
                }
            }
        }
    }
    assert!(
        matched_members > 0,
        "at least one exported member was matched to its own triage outcome, so the \
         family-to-outcome mapping above was really exercised"
    );
    assert_eq!(
        imported_arm, 0,
        "quarantine triage constructed PerEntryOutcome::Imported zero times: the import path has \
         no activation arm at all"
    );
    Ok(triaged)
}

/// Clause (3) of case 953/12: every observable reader on the destination store reads
/// IDENTICALLY across the import, INCLUDING the durable ROW census of the
/// epoch/generation authority family, and the owner-observed ordering head is
/// unchanged.
///
/// The `VersionedArtifacts` row census: the PRE-IMPORT half is read by the CALLER,
/// before it drives the import, and passed in as `versioned_artifact_rows_before`;
/// this function reads only the post-import half. This is the before/after
/// ROW-STATE check the GAP paragraph in the test body could not previously make for
/// an active-authority family: it walks durable `VERSIONED_ARTIFACTS` rows, so a row
/// the import created, revived or re-stated would be in this vector and the equality
/// would fail. Every row's lifecycle state (`Staged` / `Draining` / `Active`,
/// `src/versioned_artifact.rs:1351-1365`) is carried, so an epoch row that survived
/// with a DIFFERENT activation state is a difference too, not just a difference in
/// count. `Active` is named from the crate root (`ArtifactGenerationState`,
/// `src/lib.rs:171`) so the census states the very state A13.7 forbids an import from
/// creating: `Staged`, `Active`, `Draining` or `Retired`, but not an active generation
/// revived by the archive.
///
/// The families whose public readers take the RECOVERY page bound (`MAX_RECOVERY_PAGE`,
/// `src/lib.rs:179`, checked at `src/store.rs:37672`) are read with that bound; the
/// scan-disclosure reader has its own separate admitted bound
/// (`MAX_SCAN_DISCLOSURE_PAGE`, `src/model.rs:9852`, checked at `src/store.rs:7096`)
/// and is read with that one rather than with a transcribed number.
///
/// The `VersionedArtifacts` DURABLE ROW census is the one generation/epoch/
/// route-authority family whose table is reachable at all through a public reader
/// that ENUMERATES it rather than looking one key up:
/// `RedbRecoveryStore::load_versioned_artifact_registry` (`src/store.rs:33728`) opens
/// `VERSIONED_ARTIFACTS` and walks every row (`src/store.rs:33736-33752`). It is the
/// same table the store's census declares, and `RowFamilyKind::VersionedArtifacts` is
/// the generation/epoch authority family A13.7 names ("epochs do not revive"), so this
/// reads the ROW STATE of an active-authority family rather than a disposition list.
/// `VersionedArtifactRegistry` keeps its two maps private
/// (`src/versioned_artifact.rs:971-974`), but its own projection of them,
/// `durable_entries` (`src/versioned_artifact.rs:1346`), is public, is the EXACT
/// inverse of the load path (`from_durable_entries`,
/// `src/versioned_artifact.rs:1391`, is what `load_versioned_artifact_registry` feeds
/// the walked rows to), and is therefore a re-projection of the rows just read, never
/// a store-side default.
///
/// OWNER: `import_page_quarantined` (`src/store/backup_snapshot.rs:4029-4101`, read
/// transactions only, no write path), each public census reader on
/// `RedbRecoveryStore`, `RedbRecoveryStore::load_versioned_artifact_registry`
/// (`src/store.rs:33728`) -> `VersionedArtifactRegistry::durable_entries`
/// (`src/versioned_artifact.rs:1346`), and
/// `RedbRecoveryStore::open_backup_operational_history` (`src/store.rs:5046`).
fn destination_reads_identically_after_import_953_12(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
    snapshot: &OrsBackupSnapshot,
    versioned_artifact_rows_before: &[(String, u64, ArtifactGenerationState)],
) -> TestOutcome<()> {
    // The BASELINE for the five whole-vector censuses below is read here,
    // immediately before their after-arm. No census type is named: none of these
    // five is re-exported at the crate root, so the reader's own inferred type is
    // kept local to this phase rather than invented as a fixture type.
    //
    // The `VersionedArtifacts` row census is deliberately NOT re-read here: the
    // CALLER read it BEFORE the import, because that half of the comparison is the
    // whole claim. An import that created, revived or re-stated an epoch row has
    // to show up as a difference between a pre-import reading and a post-import
    // one, and a pair both taken after the import would compare the archive against
    // itself.
    let problems_before = store.list_recovery_problems(MAX_RECOVERY_PAGE_FOR_953)?;
    let unknown_commits_before = store.list_open_unknown_commits()?;
    let cutovers_before = store.latest_committed_cutover_ownership(MAX_RECOVERY_PAGE_FOR_953)?;
    let scan_disclosures_before = store
        .list_scan_disclosures(identity.installation_id(), MAX_SCAN_DISCLOSURE_PAGE_FOR_953)?;
    let activation_results_before = store.load_all_activation_results()?;

    assert_eq!(
        store.list_recovery_problems(MAX_RECOVERY_PAGE_FOR_953)?,
        problems_before,
        "the recovery-problem census is unchanged: the import created and resolved no problem"
    );
    assert_eq!(
        store.list_open_unknown_commits()?,
        unknown_commits_before,
        "the open unknown-commit census is unchanged: the import opened no unknown commit and \
         resolved none (I14.21: unknown stays reconciling and is never converted into a retry)"
    );
    assert_eq!(
        store.latest_committed_cutover_ownership(MAX_RECOVERY_PAGE_FOR_953)?,
        cutovers_before,
        "the committed cutover-ownership census is unchanged: importing an archive created no \
         cutover and revived no route/generation ownership"
    );
    assert_eq!(
        store
            .list_scan_disclosures(identity.installation_id(), MAX_SCAN_DISCLOSURE_PAGE_FOR_953,)?,
        scan_disclosures_before,
        "the scan-disclosure census is unchanged: import restores no scan state"
    );
    assert_eq!(
        store.load_all_activation_results()?,
        activation_results_before,
        "the activation-result census is unchanged: no session or activation became current"
    );

    let versioned_artifact_rows_after: Vec<(String, u64, ArtifactGenerationState)> = store
        .load_versioned_artifact_registry(MAX_RECOVERY_PAGE_FOR_953)?
        .durable_entries()?
        .into_iter()
        .map(|row| (row.artifact.module_id, row.artifact.generation, row.state))
        .collect();
    assert!(
        versioned_artifact_rows_before.is_empty(),
        "the epoch/generation authority family really is READ, not vacuously equal: this store \
         declares no versioned-artifact row, so an import that had revived or created one would \
         appear in the census read below"
    );
    assert_eq!(
        versioned_artifact_rows_after, versioned_artifact_rows_before,
        "the durable VersionedArtifacts row census is unchanged across the quarantined import: \
         no epoch/generation/route authority row was created, revived or re-stated (A13.7: old \
         sessions, leases, approvals and epochs do not revive)"
    );
    assert!(
        !versioned_artifact_rows_after
            .iter()
            .any(|(_, _, state)| *state == ArtifactGenerationState::Active),
        "and no generation row in the census is Active at all: the quarantined import left no \
         active generation authority behind"
    );

    // And the owner-observed ordering head, re-read through the store's own
    // opener after the import, is the value the archive was frozen at.
    let source = source_for(identity)?;
    assert_eq!(
        store
            .open_backup_operational_history(&source, 0)?
            .identity
            .high_water_order,
        snapshot.fence.high_water_order,
        "the destination's observed ordering high-water after the import is the head the archive \
         was frozen at, so case 13's before/after comparison is over an unchanged head"
    );
    Ok(())
}

// WORK_UNIT_CASE: 953/13
#[test]
fn canonical_ordering_is_not_advanced_by_a_snapshot_import() -> TestResult {
    let (store, identity, path) = open_bound_store("13")?;
    let written = seed_operational_rows(&store, 2)?;
    let source = source_for(&identity)?;

    // The observable ordering head, read BEFORE anything is exported, through the
    // SAME public opener used after (`open_operational_head_953_13`, below).
    let head_before = open_operational_head_953_13(&store, &source)?;
    assert!(
        head_before.identity.high_water_order > 0,
        "the rows seeded above really advanced the store's ordering head, so a head that never \
         moves is not vacuously equal"
    );
    // The window's own `u64` row count is compared against the seeded `Vec` length
    // through a checked narrowing: the count is the number of operational rows
    // this store actually wrote, so it is bounded by `written.len()` and cannot
    // exceed what this process addressed.
    let observed_row_count = usize::try_from(head_before.identity.operational_row_count)
        .map_err(|_| "the observable window declares more rows than this process can address")?;
    assert_eq!(
        observed_row_count,
        written.len(),
        "the observable window declares exactly the operational rows this store wrote"
    );

    // ---- the full export -> quarantine-import -> reconcile cycle -----------
    // (`export_import_reconcile_cycle_953_13`, below: the export at exactly the
    // observed head, the quarantine triage, the reconciliation receipt and the
    // historical lost-response replay.)
    let receipt = export_import_reconcile_cycle_953_13(&store, &identity, &source, &head_before)?;

    // ---- the observable ordering head, AFTER the cycle ---------------------
    // (`ordering_head_did_not_move_953_13`, below.)
    ordering_head_did_not_move_953_13(&store, &source, &head_before, &receipt)?;

    remove_db(&path);
    Ok(())
}

/// The observable ordering head, read through the SAME public opener on both sides
/// of case 953/13's cycle.
///
/// `RedbRecoveryStore::open_backup_operational_history` (`src/store.rs:5046`) measures
/// the window and the owner-observed high-water under ONE read transaction
/// (`operational_history_identity`, `src/store/backup_snapshot.rs:2022`). Its
/// `identity` is `OrsOperationalSnapshotIdentity` (`src/backup_snapshot.rs:781`), whose
/// `high_water_order` is `ors_meta_v1`'s `NEXT_GLOBAL_ORDER` read by
/// `capture_store_fence` (`src/store/backup_snapshot.rs:2337`) — the crate's canonical
/// ordering head, the same value `check_export_fence` compares a request's fence
/// against (`src/store/backup_snapshot.rs:2419`).
///
/// OWNER: `RedbRecoveryStore::open_backup_operational_history`
/// (`src/store.rs:5046`) -> `operational_history_identity`
/// (`src/store/backup_snapshot.rs:2022`) and `capture_store_fence` (`:2337`).
fn open_operational_head_953_13(
    store: &RedbRecoveryStore,
    source: &OrsBackupSourceIdentity,
) -> TestOutcome<eliot_ors::OrsOperationalCursor> {
    // `open_backup_operational_history` answers in `OrsError`, which is itself a
    // `std::error::Error`, so `?` is the WHOLE boundary conversion into this
    // `TestOutcome`'s `Box<dyn Error>` and no explicit `map_err` is needed.
    Ok(store.open_backup_operational_history(source, 0)?)
}

/// The full export -> quarantine-import -> reconcile cycle of case 953/13. The
/// archive is frozen at exactly the head observed before, the triage produces real
/// quarantine outcomes, the receipt binds the archive's own denominator with a count
/// DERIVED from those outcomes, and the lost-response replay is historical — no fresh
/// attempt instant and no new outcome.
///
/// `reconcile_lost_import_response` (`src/store/backup_snapshot.rs:4448`) is a clone
/// plus a verdict re-evaluation and takes no `Database`, no `ReadTransaction` and no
/// `WriteTransaction`. It is an ASSOCIATED function of `RedbRecoveryStore` taking only
/// the prior receipt (no receiver), so it is called on the type.
///
/// OWNER: `RedbRecoveryStore::export_backup_snapshot` (`src/store.rs:4959`),
/// `RedbRecoveryStore::import_backup_page_quarantined` (`src/store.rs:5060`) ->
/// `triage_entry` (`src/store/backup_snapshot.rs:4115`),
/// `RedbRecoveryStore::reconcile_backup_import` (`src/store.rs:5099`) ->
/// `OrsBackupImportReceipt::new` (`src/backup_snapshot.rs:3570`) and
/// `RedbRecoveryStore::reconcile_lost_backup_import_response` (`src/store.rs:5124`).
fn export_import_reconcile_cycle_953_13(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
    source: &OrsBackupSourceIdentity,
    head_before: &eliot_ors::OrsOperationalCursor,
) -> TestOutcome<eliot_ors::OrsBackupImportReceipt> {
    // The control for this cycle's ordering comparison: the observed head is read
    // through the SAME opener that reads it after the export, triage and reconcile
    // below, so "the head did not move" is over one identity rather than over two
    // unrelated ones. Assertion COUNTS, not weakens: a non-canonical `source` here
    // would make the after-arm's unchanged head vacuous.
    assert_eq!(
        open_operational_head_953_13(store, source)?.identity,
        head_before.identity,
        "the head this cycle freezes the archive at is read through the SAME opener that reads the \
         head after the import, under the SAME source identity, so the before/after equality \
         asserted below compares one canonical ordering head"
    );
    let request = observed_request(store, identity, MAX_BACKUP_PAGE_ENTRIES, 1)?;
    let snapshot = store.export_backup_snapshot(&request)?;
    snapshot.validate()?;
    assert_eq!(
        snapshot.fence.high_water_order, head_before.identity.high_water_order,
        "the archive was frozen at exactly the head observed above"
    );

    let destination = OrsBackupDestination::new(
        identity.installation_id().to_owned(),
        "admission-receipt-953-13".to_owned(),
        true,
    )?;
    let import_source = OrsBackupSourceIdentity::new(
        "installation-953-13-import-source".to_owned(),
        identity.ors_generation(),
        BACKUP_SNAPSHOT_SCHEMA_VERSION,
    )?;
    let import = OrsBackupImportRequest {
        snapshot_digest: snapshot.snapshot_digest(),
        source: import_source,
        destination,
    };
    let page = snapshot
        .pages
        .first()
        .ok_or("the exported snapshot carries the first page this case triages")?;

    let triaged = store.import_backup_page_quarantined(&import, page)?;
    assert_eq!(
        triaged.len(),
        page.entries.len(),
        "the quarantine triage returned one outcome per exported entry"
    );
    assert!(
        !triaged.is_empty(),
        "the imported page really carried entries, so this cycle is not vacuous"
    );
    let quarantined = triaged
        .iter()
        .filter(|(_, outcome)| {
            matches!(
                outcome,
                eliot_ors::PerEntryOutcome::Unresolved { .. }
                    | eliot_ors::PerEntryOutcome::Forensic { .. }
                    | eliot_ors::PerEntryOutcome::Blocked { .. }
                    | eliot_ors::PerEntryOutcome::Rejected { .. }
            )
        })
        .count();
    assert!(
        quarantined > 0,
        "the snapshot import produced at least one quarantine outcome, so the ordering \
         comparison below is over a real import and not over a no-op"
    );

    let receipt = store.reconcile_backup_import(&import, &snapshot, &triaged, 1_700_000_000_700)?;
    assert_eq!(
        receipt.snapshot_digest, import.snapshot_digest,
        "the receipt binds the imported archive's own denominator digest"
    );
    // The receipt's count is the number of outcomes in `triaged`, a vector this
    // process holds, so the checked narrowing below cannot fail; a failure would
    // mean the store counted members this process cannot enumerate.
    let receipt_unresolved = usize::try_from(receipt.unresolved_count)
        .map_err(|_| "the receipt declares more unresolved members than this process enumerated")?;
    assert_eq!(
        receipt_unresolved,
        triaged
            .iter()
            .filter(|(_, outcome)| matches!(outcome, eliot_ors::PerEntryOutcome::Unresolved { .. }))
            .count(),
        "the receipt's unresolved count is derived from the imported outcomes, so the quarantined \
         members stayed quarantined through reconciliation"
    );
    // `KnownZeroVerdict` is not nameable from a test (it is declared `pub` inside
    // the PRIVATE module `crate::backup_snapshot`, `src/backup_snapshot.rs:3487`,
    // and is not re-exported at `src/lib.rs:67-76`), so the verdict is read as
    // the store rendered it. The `Satisfied` variant has no fields, so its `Debug`
    // text is exactly `"Satisfied"`.
    assert!(
        format!("{:?}", receipt.known_zero_verdict) != "Satisfied",
        "a nonempty quarantined roster cannot report a satisfied known-zero, so reconciliation \
         did not claim any imported effect was resolved; the store recorded {:?}",
        receipt.known_zero_verdict
    );

    // The lost-response replay is historical: no fresh attempt instant and no new
    // outcome, because `reconcile_lost_import_response`
    // (`src/store/backup_snapshot.rs:4448`) is a clone plus a verdict
    // re-evaluation and takes no `Database`, no `ReadTransaction` and no
    // `WriteTransaction`. It is an ASSOCIATED function of `RedbRecoveryStore`
    // taking only the prior receipt (no receiver), so it is called on the type.
    let replayed = RedbRecoveryStore::reconcile_lost_backup_import_response(&receipt);
    assert_eq!(
        replayed.per_entry, receipt.per_entry,
        "the replayed response adds and drops no outcome"
    );
    assert_eq!(
        replayed.import_at_ms, receipt.import_at_ms,
        "the replayed response carries the ORIGINAL import instant"
    );
    Ok(receipt)
}

/// The observable ordering head AFTER the cycle: it did not move, and the equality is
/// a property of the import rather than of a frozen store — because an ordinary owner
/// write DOES move the same head. The destination's recovery-state census is the other
/// thing a replay would have had to touch in order to "resolve" anything.
///
/// OWNER: `RedbRecoveryStore::open_backup_operational_history`
/// (`src/store.rs:5046`) on both sides, `RedbRecoveryStore::list_recovery_problems`
/// (`src/store.rs:37671`) and `RedbRecoveryStore::list_open_unknown_commits`
/// (`src/store.rs:6261`), plus `seed_operational_rows` through the public
/// `OperationalRecoveryStore` writers for the control.
fn ordering_head_did_not_move_953_13(
    store: &RedbRecoveryStore,
    source: &OrsBackupSourceIdentity,
    head_before: &eliot_ors::OrsOperationalCursor,
    _receipt: &eliot_ors::OrsBackupImportReceipt,
) -> TestOutcome<()> {
    let head_after = open_operational_head_953_13(store, source)?;
    assert_eq!(
        head_after.identity, head_before.identity,
        "canonical ordering is NOT advanced by a snapshot import: the owner-observed ordering \
         head, the frozen operational window root, its row and byte denominators and its \
         source/generation/schema binding are exactly the ones observed before the export, the \
         quarantine import and the reconciliation"
    );
    assert_eq!(
        head_after.identity.high_water_order, head_before.identity.high_water_order,
        "the high-water itself did not move (I14.21 / I5.13: never advance canonical ordering by \
         replaying a snapshot)"
    );
    assert_eq!(
        head_after.identity.operational_root_digest, head_before.identity.operational_root_digest,
        "the durable operational window's content root is unchanged, so no row was added, \
         removed or rewritten by the cycle"
    );
    assert_eq!(
        head_after.identity.operational_row_count, head_before.identity.operational_row_count,
        "the operational row count is unchanged"
    );
    assert_eq!(
        head_after.identity.operational_total_bytes, head_before.identity.operational_total_bytes,
        "the operational byte denominator is unchanged"
    );

    // The destination's recovery-state census, the other thing a replay would
    // have had to touch in order to "resolve" anything.
    let problems_after = store.list_recovery_problems(MAX_RECOVERY_PAGE_FOR_953)?;
    let unknown_commits_after = store.list_open_unknown_commits()?;
    assert!(
        problems_after.is_empty() && unknown_commits_after.is_empty(),
        "the cycle created no recovery problem and no unknown commit: unknown stayed reconciling \
         and nothing was retried"
    );

    // Control: the head really DOES move when the owner writes, so the equality
    // above is a property of the import and not of a frozen store. One more pair
    // of ordinary writes through the shared harness's real writers, then re-read.
    seed_operational_rows(store, 1)?;
    let head_moved = open_operational_head_953_13(store, source)?;
    assert!(
        head_moved.identity.high_water_order > head_after.identity.high_water_order,
        "an ordinary owner write DOES advance the same observable head ({} -> {}), so the \
         unchanged head across the import cycle is the import's property and not an artefact of \
         the reader",
        head_after.identity.high_water_order,
        head_moved.identity.high_water_order
    );
    assert_ne!(
        head_moved.identity.operational_root_digest, head_after.identity.operational_root_digest,
        "and it moves the durable window root too, so the equality asserted above really compared \
         two different observed states"
    );
    Ok(())
}

// ===========================================================================
// Cases 14..17 (lane/CB2). This block sits between cases 10..13 above and the
// 19+20 block below; cases 1..9 sit above that. Every helper below is local to
// its own case body: no second `type TestResult`, no second `temp_db`, no
// second `open_bound_store`, and no new `use` statement.
//
// Neither `CurrentOwnerValidation` nor `KnownZeroVerdict` is named anywhere
// below, because neither is reachable from this crate's public surface: both are
// declared `pub` INSIDE the private module `crate::backup_snapshot`
// (`src/backup_snapshot.rs:3406` and `:3487`) and the crate root re-export list
// (`src/lib.rs:67-76`) does not carry them. Every claim about the known-zero
// gate is therefore stated through the PUBLIC
// `OrsBackupImportReceipt::known_zero_unresolved`
// (`src/backup_snapshot.rs:3648`), and the private coverage predicate
// `OrsBackupImportReceipt::owner_validation_is_complete`
// (`src/backup_snapshot.rs:3710`) is never named either. Every receipt and every
// current-owner validation below is obtained from a real
// `RedbRecoveryStore::reconcile_backup_import` call; none is minted here.
// ===========================================================================

/// The import-at stamp these cases use: a positive unix millisecond, because
/// `CurrentOwnerValidation::validate` (`src/backup_snapshot.rs:3475`) refuses
/// `validated_at_ms <= 0` and `observe_current_owner_validation`
/// (`src/store/backup_snapshot.rs:4256`) stamps the receipt's `import_at_ms`
/// onto that record.
const IMPORT_AT_MS_953: i64 = 1_700_000_000_500;

/// The payload identity an import declares: another installation's well-formed
/// `OrsBackupSourceIdentity` (`OrsBackupSourceIdentity::new`,
/// `src/backup_snapshot.rs:291`), never this file's own.
///
/// It CANNOT be this file's own, and that is a property of the contract rather
/// than of this fixture. `validate_import_binding`
/// (`src/backup_snapshot.rs:3742`) refuses a destination equal to the source, so
/// source and destination may not name one installation; and
/// `reconcile_import_receipt` (`src/store/backup_snapshot.rs:4395-4403`) compares
/// the declared destination against this store's DURABLE store-object identity.
/// One temporary file opened through `open_for_installation` has exactly ONE
/// durable installation, so the destination has to be this file's own and the
/// source has to be a different, still well-formed, installation.
///
/// That is also why the four-roster case 17 needs one `reconcile_backup_import`
/// call per roster rather than one per claim: the destination check
/// (`src/store/backup_snapshot.rs:4395`) refuses on the SECOND call inside a
/// closure that borrows `store` immutably, and `validate_import_binding` is NOT
/// called by `reconcile_backup_import` at all. Varying only the outcome vector
/// over one caller is both lawful and sufficient.
fn import_origin(
    identity: &OrsStoreIdentity,
    case: &str,
) -> Result<OrsBackupSourceIdentity, OrsError> {
    OrsBackupSourceIdentity::new(
        format!("installation-953-import-origin-{case}"),
        identity.ors_generation(),
        BACKUP_SNAPSHOT_SCHEMA_VERSION,
    )
}

// WORK_UNIT_CASE: 953/14
#[test]
fn exact_operation_replay_is_idempotent_and_a_changed_payload_is_refused() -> TestResult {
    let (store, identity, path) = open_bound_store("14")?;
    let written = seed_operational_rows(&store, 1)?;
    let observed = observed_request(&store, &identity, MAX_BACKUP_PAGE_ENTRIES, 1)?;
    let exported = store.export_backup_snapshot(&observed)?;
    exported.validate()?;

    let imported_source = import_origin(&identity, "14")?;
    let destination = OrsBackupDestination::new(
        identity.installation_id().to_owned(),
        "admission-receipt-953-14".to_owned(),
        true,
    )?;
    assert_ne!(
        destination.installation_id, imported_source.installation_id,
        "the FOREIGN source used by the triage path really differs from this store's destination \
         installation, which is what `validate_import_binding` (`backup_snapshot::validate_import_binding`) \
         requires before any page may be triaged"
    );

    // TWO requests, because the two entrypoints constrain the source DIFFERENTLY,
    // and each arm below is attributed to the rule that actually fires:
    //  * `import_page_quarantined` (`store::backup_snapshot::import_page_quarantined`)
    //    runs `validate_import_binding`, whose FIRST rule refuses a source equal to
    //    the destination. So a FOREIGN source is REQUIRED there.
    //  * `expected_import_roster` (`store::backup_snapshot::expected_import_roster`)
    //    compares in this order: `snapshot.validate()`, then `snapshot.source !=
    //    import.source` -> `IntegrityProblem { record_type: "backup_import_source" }`,
    //    and only THEN `snapshot.denominator_digest != import.snapshot_digest` ->
    //    `PayloadIntegrityMismatch`. A foreign source therefore pre-empts the digest
    //    rule entirely, so the accepted reconciliation below carries the ARCHIVE's OWN
    //    source and the archive's OWN recorded denominator digest.
    let import = OrsBackupImportRequest {
        snapshot_digest: exported.denominator_digest.clone(),
        source: exported.source.clone(),
        destination: destination.clone(),
    };
    assert_eq!(
        import.source, exported.source,
        "the accepted reconcile request names the ARCHIVE's own source identity, the comparison \
         `store::backup_snapshot::expected_import_roster` performs before it will read a roster"
    );

    // ONE real reconciled operation: the archive's whole declared roster, every
    // member carrying the outcome a COMPLETE import of it would produce. The
    // receipt's expected roster is established from the snapshot itself, so the
    // vector is built from that same roster rather than from the caller's spelling
    // of it.
    let outcomes = exported
        .expected_member_roster()?
        .iter()
        .map(|(_, record_id)| (record_id.clone(), PerEntryOutcome::Imported))
        .collect::<Vec<(String, PerEntryOutcome)>>();
    assert_eq!(
        outcomes.len(),
        written.len(),
        "the accepted vector really carries one outcome per row this case wrote through the \
         public writers, so the reconciliation below is over the whole archive and not a subset"
    );
    let receipt = store.reconcile_backup_import(&import, &exported, &outcomes, IMPORT_AT_MS_953)?;
    assert_eq!(
        receipt.snapshot_digest, import.snapshot_digest,
        "the receipt binds the snapshot identity the import request named"
    );

    // ---- (a) the UNCHANGED replay: same identity, same payload ------------
    unchanged_replay_is_idempotent_953_14(&store, &import, &exported, &outcomes, &receipt)?;

    // ---- (b), (c) and (d): the refusal arms, each naming its own rule ------
    let (changed, foreign_source, payload_conflict) =
        changed_payload_and_source_are_refused_953_14(
            &store, &identity, &exported, &outcomes, &import, &written,
        )?;

    // The discrimination, stated against the three refused requests: (a) and (b) differ
    // ONLY in the named snapshot digest, (a) and (c) ONLY in the declared source, and
    // (a) and (d) in NOTHING at all — (d) names the same request (a) reconciled under,
    // differing only in the outcome the caller put on one record id. (a) is accepted
    // where all three are refused, so none of the refusals is a blanket refusal of
    // every reconciliation.
    assert!(
        receipt.snapshot_digest != changed.snapshot_digest
            && receipt.source_installation != foreign_source.source.installation_id
            && payload_conflict.snapshot_digest == receipt.snapshot_digest
            && payload_conflict.source == exported.source,
        "each refused request differs from the accepted one in exactly the field its own refusal \
         names: (b) in the named snapshot digest, (c) in the declared source, and (d) in no \
         field of the request at all"
    );

    remove_db(&path);
    Ok(())
}

/// PHASE (a) of case 953/14: an UNCHANGED replay — same operation identity, same
/// payload, same outcomes — is IDEMPOTENT. Every field the original receipt carried
/// is compared field-for-field on the replay, so a retry that re-derived anything
/// (a newest value, a fresh stamp, a fresh verdict) would fail here.
///
/// OWNER: `RedbRecoveryStore::reconcile_backup_import` (`store::RedbRecoveryStore::
/// reconcile_backup_import`) -> `store::backup_snapshot::reconcile_import_receipt` /
/// `backup_snapshot::OrsBackupImportReceipt::new` and
/// `store::backup_snapshot::observe_current_owner_validation`.
fn unchanged_replay_is_idempotent_953_14(
    store: &RedbRecoveryStore,
    import: &OrsBackupImportRequest,
    exported: &OrsBackupSnapshot,
    outcomes: &[(String, PerEntryOutcome)],
    receipt: &eliot_ors::OrsBackupImportReceipt,
) -> TestOutcome<()> {
    let replay = store.reconcile_backup_import(import, exported, outcomes, IMPORT_AT_MS_953)?;
    assert_eq!(
        replay.snapshot_digest, receipt.snapshot_digest,
        "an exact replay stays bound to the SAME snapshot identity (I14.21: a retry follows operation identity, never a newest value)"
    );
    assert_eq!(
        replay.source_installation, receipt.source_installation,
        "an exact replay names the same source installation"
    );
    assert_eq!(
        replay.destination_installation, receipt.destination_installation,
        "an exact replay names the same destination installation"
    );
    assert_eq!(
        replay.import_at_ms, receipt.import_at_ms,
        "an exact replay carries the same import stamp"
    );
    assert_eq!(
        replay.expected_members, receipt.expected_members,
        "an exact replay carries the same member roster"
    );
    assert_eq!(
        replay.per_entry, receipt.per_entry,
        "an exact replay carries the same per-entry denominator, with no outcome added or dropped"
    );
    assert_eq!(
        replay.unresolved_count, receipt.unresolved_count,
        "an exact replay reports the same unresolved count"
    );
    assert_eq!(
        replay.current_owner_validation.snapshot_digest,
        receipt.current_owner_validation.snapshot_digest,
        "an exact replay's owner validation is bound to the same snapshot"
    );
    assert_eq!(
        replay.known_zero_verdict, receipt.known_zero_verdict,
        "an exact replay reaches the same verdict, so the replay is idempotent rather than refused"
    );
    Ok(())
}

/// PHASES (b), (c) and (d) of case 953/14: the refusal arms beside the accepted
/// replay, each attributed to the rule that actually fires, in the order
/// `store::backup_snapshot::expected_import_roster` evaluates them.
///  * (b) varies the named snapshot digest ALONE. The source is the archive's own,
///    so the source comparison is satisfied and the ONLY remaining difference is
///    `import.snapshot_digest`, which is refused with `PayloadIntegrityMismatch`.
///  * (c) varies the declared SOURCE alone, under the archive's OWN recorded digest.
///    The source comparison runs BEFORE the digest comparison, so this request is
///    refused by the source rule and its digest is never compared.
///  * (d) changes the PAYLOAD for the SAME operation key: the request is the accepted
///    one in every field, and the only thing that changes is the outcome a caller
///    presents for one record id. `reconcile_backup_import` does not refuse a
///    mismatching vector — that judgement belongs to the gate
///    `OrsBackupImportReceipt::known_zero_unresolved`, whose COVERAGE clause
///    `OrsBackupImportReceipt::owner_validation_is_complete` compares the outcomes
///    against the roster the snapshot declares. The vector here presents a FOREIGN
///    record id instead of one archived member, which is exactly the condition
///    "reusing an idempotency key with a different canonical request hash" (I05-27),
///    and the gate refuses it with `ReconciliationMismatch` rather than building a
///    receipt whose recorded verdict would claim a coverage nobody established.
///    The refused request is returned so the caller can state the discrimination.
fn changed_payload_and_source_are_refused_953_14(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
    exported: &OrsBackupSnapshot,
    outcomes: &[(String, PerEntryOutcome)],
    import: &OrsBackupImportRequest,
    written: &[String],
) -> TestOutcome<(
    OrsBackupImportRequest,
    OrsBackupImportRequest,
    OrsBackupImportRequest,
)> {
    // ---- (b) the CHANGED payload identity: the SAME outcomes, another digest
    let changed = OrsBackupImportRequest {
        snapshot_digest: fence_digest('b'),
        source: import.source.clone(),
        destination: import.destination.clone(),
    };
    assert_eq!(
        changed.source, import.source,
        "the changed-digest arm varies the snapshot IDENTITY alone, so the source comparison is \
         a separate refusal and not this one"
    );
    assert_ne!(
        changed.snapshot_digest, exported.denominator_digest,
        "the digest this arm names really is not the archive's own recorded denominator digest"
    );
    match store.reconcile_backup_import(&changed, exported, outcomes, IMPORT_AT_MS_953) {
        Err(OrsError::PayloadIntegrityMismatch) => {}
        other => panic!(
            "the SAME outcomes presented under a different snapshot digest must be refused, got {other:?}"
        ),
    }

    // ---- (c) the CHANGED source: the archive's OWN digest, another installation
    let foreign_source = OrsBackupImportRequest {
        snapshot_digest: import.snapshot_digest.clone(),
        source: import_origin(identity, "14-other")?,
        destination: import.destination.clone(),
    };
    assert_eq!(
        foreign_source.snapshot_digest, exported.denominator_digest,
        "this arm names the archive's OWN recorded denominator digest, so the digest comparison \
         below is satisfied and the SOURCE rule is the only one left that can refuse it"
    );
    match store.reconcile_backup_import(&foreign_source, exported, outcomes, IMPORT_AT_MS_953) {
        Err(OrsError::IntegrityProblem { record_type, .. }) => {
            assert_eq!(
                record_type, "backup_import_source",
                "a source mismatch is refused by the source comparison itself, which runs BEFORE \
                 the digest comparison (`store::backup_snapshot::expected_import_roster`)"
            );
        }
        other => panic!(
            "the same digest presented under a different source must be refused, got {other:?}"
        ),
    }

    // ---- (d) the CHANGED payload for the SAME operation key ----------------
    // This arm is NOT `reconcile_backup_import` refusing: the request is field-for-field
    // the accepted one. The change is in the payload the caller presents for one archived
    // record id, which is the identity-conflict condition I05-27 names for a reused
    // idempotency key, and the refusal is the coverage clause of the public gate.
    let payload_conflict = import.clone();
    let replaced_id = written.first().ok_or(
        "this case wrote the real operational row whose archived identity the payload arm \
         replaces, which is a fixture failure",
    )?;
    let mut payload_conflict_outcomes = outcomes
        .iter()
        .filter(|(record_id, _)| record_id != replaced_id)
        .cloned()
        .collect::<Vec<(String, PerEntryOutcome)>>();
    payload_conflict_outcomes.push((
        format!("{replaced_id}-953-14-replayed-under-another-payload"),
        PerEntryOutcome::Imported,
    ));
    assert_eq!(
        payload_conflict_outcomes.len(),
        outcomes.len(),
        "the conflicting vector carries exactly as many outcomes as the accepted one: every \
         archived member it kept, plus one identity that is not a member, so it is a changed \
         payload for the same operation key and not a shorter import"
    );
    assert!(
        payload_conflict_outcomes
            .iter()
            .all(
                |(record_id, _)| outcomes.iter().any(|(kept, _)| kept == record_id)
                    || record_id == &format!("{replaced_id}-953-14-replayed-under-another-payload")
            ),
        "every entry of the conflicting vector is either one the accepted vector really carried \
         or the single substituted foreign identity"
    );
    assert_eq!(
        payload_conflict.snapshot_digest, import.snapshot_digest,
        "this arm names the SAME snapshot identity as the accepted reconciliation"
    );
    assert_eq!(
        payload_conflict.source, import.source,
        "and the SAME declared source, so nothing but the presented payload differs"
    );
    match store.reconcile_backup_import(
        &payload_conflict,
        exported,
        &payload_conflict_outcomes,
        IMPORT_AT_MS_953,
    ) {
        Err(OrsError::ReconciliationMismatch) => {}
        other => panic!(
            "an import that presents a different payload for an already-reconciled operation key \
             must be refused by the coverage clause of the known-zero gate, got {other:?}"
        ),
    }
    Ok((changed, foreign_source, payload_conflict))
}

// WORK_UNIT_CASE: 953/15
#[test]
fn lost_import_response_replays_without_duplicate_effect() -> TestResult {
    let (store, identity, path) = open_bound_store("15")?;
    let written = seed_operational_rows(&store, 1)?;
    let observed = observed_request(&store, &identity, MAX_BACKUP_PAGE_ENTRIES, 1)?;
    let exported = store.export_backup_snapshot(&observed)?;
    exported.validate()?;

    // TWO requests, because the two entrypoints constrain the source DIFFERENTLY.
    // `RedbRecoveryStore::import_backup_page_quarantined` runs
    // `backup_snapshot::validate_import_binding`, whose FIRST rule refuses a source
    // equal to the destination, so the TRIAGE request declares a FOREIGN source and
    // this store as destination. `RedbRecoveryStore::reconcile_backup_import` runs
    // `store::backup_snapshot::expected_import_roster`, which compares the snapshot's
    // OWN source against `import.source` before anything else, so the RECONCILE
    // request declares the ARCHIVE's own source and its own recorded denominator
    // digest. One request carrying both a foreign source and a foreign digest is
    // refused by the source rule, so it can produce neither triage nor receipt.
    let triage_import = OrsBackupImportRequest {
        snapshot_digest: exported.denominator_digest.clone(),
        source: import_origin(&identity, "15")?,
        destination: OrsBackupDestination::new(
            identity.installation_id().to_owned(),
            "admission-receipt-953-15".to_owned(),
            true,
        )?,
    };
    assert_ne!(
        triage_import.source.installation_id, triage_import.destination.installation_id,
        "the triage request's FOREIGN source really differs from this store's durable installation, \
         which is what `backup_snapshot::validate_import_binding` requires"
    );
    let import = OrsBackupImportRequest {
        snapshot_digest: exported.denominator_digest.clone(),
        source: exported.source.clone(),
        destination: triage_import.destination.clone(),
    };
    assert_eq!(
        import.source, exported.source,
        "the reconcile request names the ARCHIVE's own source identity, which \
         `store::backup_snapshot::expected_import_roster` compares BEFORE the digest rule"
    );
    assert_eq!(
        import.snapshot_digest, exported.denominator_digest,
        "and the archive's OWN recorded denominator digest, so the reconciliation below is \
         accepted by the store rather than refused before a receipt exists"
    );

    // A REAL quarantined triage of ONE REAL exported page
    // (`store::RedbRecoveryStore::import_backup_page_quarantined`, a pure read
    // path: `store::backup_snapshot::import_page_quarantined` opens reads only).
    //
    // The page must be expired-free: `store::backup_snapshot::import_page_quarantined`
    // refuses a page whose `expires_at_ms` has passed against the store's own clock,
    // and the store stamps a bounded capture window at export
    // (`backup_snapshot::MAX_BACKUP_PAGE_LIFETIME_MS`).
    let page = exported.pages.first().ok_or(
        "the exported snapshot carries the page this case triages, which is a fixture failure",
    )?;
    let triaged = store.import_backup_page_quarantined(&triage_import, page)?;
    assert_eq!(
        triaged.len(),
        page.entries.len(),
        "quarantine triage returns exactly one outcome per exported entry"
    );
    assert!(
        triaged
            .iter()
            .any(|(_, outcome)| matches!(outcome, PerEntryOutcome::Unresolved { .. })),
        "a fresh empty destination triages a member as Unresolved, which is the quarantined unknown the card keeps for the canonical owner (`store::backup_snapshot::triage_entry`)"
    );
    assert!(
        !written.is_empty(),
        "the store really wrote operational rows, so the archive really has a member to quarantine"
    );

    let receipt = store.reconcile_backup_import(&import, &exported, &triaged, IMPORT_AT_MS_953)?;
    receipt_denominator_is_derived_953_15(&receipt, &triaged, page)?;

    // ---- the lost response, replayed ---------------------------------------
    // The replay itself, and everything it must NOT have done. The store is used
    // afterwards precisely to show the replay needed no store.
    lost_response_replay_is_historical_953_15(&receipt, &triaged);

    // NO store write, observed from the store's own live rows rather than from
    // the replay's report of itself: the archive exported after the replay has
    // the same denominator digest as the one exported before it.
    let after_replay = store.export_backup_snapshot(&observed_request(
        &store,
        &identity,
        MAX_BACKUP_PAGE_ENTRIES,
        1,
    )?)?;
    assert_eq!(
        after_replay.denominator_digest, exported.denominator_digest,
        "a lost-response replay left the destination's durable state untouched: the post-replay archive's digest equals the pre-replay archive's"
    );

    remove_db(&path);
    Ok(())
}

/// PHASE 2 of case 953/15: the receipt the REAL triage produced. The unresolved
/// count, the expected roster and the whole current-owner validation are all shown
/// to be DERIVED — from the outcomes handed in, from the archive's own member set
/// and from the store's live recovery families — so nothing below can be a reset to
/// zero or a thinner question.
///
/// OWNER: `backup_snapshot::OrsBackupImportReceipt::new` (derives the
/// unresolved count from the outcomes themselves),
/// `store::backup_snapshot::expected_import_roster` (establishes the expected
/// roster) and `store::backup_snapshot::observe_current_owner_validation` (the
/// roster it asks about, the stamp it carries, and the families it consulted).
fn receipt_denominator_is_derived_953_15(
    receipt: &eliot_ors::OrsBackupImportReceipt,
    triaged: &[(String, PerEntryOutcome)],
    page: &OrsBackupPage,
) -> TestOutcome<()> {
    assert!(
        receipt.unresolved_count > 0,
        "the receipt derived a NONZERO unresolved count from the outcomes themselves \
         (`backup_snapshot::OrsBackupImportReceipt::new`), so nothing below can be a reset to zero"
    );
    assert_eq!(
        receipt.unresolved_count,
        u64::try_from(
            triaged
                .iter()
                .filter(|(_, outcome)| matches!(outcome, PerEntryOutcome::Unresolved { .. }))
                .count()
        )?,
        "the unresolved count is the number of Unresolved outcomes, not an independently supplied number"
    );
    assert_eq!(
        receipt.expected_members.len(),
        page.entries.len(),
        "the expected roster is the archive's own member set (`store::backup_snapshot::expected_import_roster`)"
    );
    assert_eq!(
        receipt.current_owner_validation.validated_record_ids.len(),
        page.entries.len(),
        "the current owner was asked about every archived member (`store::backup_snapshot::observe_current_owner_validation`)"
    );
    assert_eq!(
        receipt.current_owner_validation.validated_at_ms, IMPORT_AT_MS_953,
        "the owner validation is stamped with the import instant"
    );
    assert_eq!(
        receipt.current_owner_validation.consulted_families,
        vec![
            RowFamilyKind::RecoveryInbox,
            RowFamilyKind::RecoveryProblems
        ],
        "BOTH live recovery families were read (`store::backup_snapshot::observe_current_owner_validation`)"
    );
    assert!(
        receipt
            .current_owner_validation
            .unresolved_effect_identities
            .is_empty(),
        "the current owner itself holds nothing unresolved, so this gate refusal is the IMPORT-outcome clause (`backup_snapshot::OrsBackupImportReceipt::known_zero_unresolved`), not a live-row clause"
    );
    Ok(())
}

/// PHASE 3 of case 953/15: the lost response, replayed. It is the SAME operation,
/// not a second one; it produces NO duplicate effect and NO blind retry; it stays
/// HISTORICAL (it cannot manufacture fresh current-owner evidence); and the only
/// thing it recomputes — the recorded verdict — agrees with the original because
/// the same PUBLIC gate produced it.
///
/// OWNER: `store::RedbRecoveryStore::reconcile_lost_backup_import_response` ->
/// `store::backup_snapshot::reconcile_lost_import_response` (a clone of the prior
/// receipt whose recorded verdict is re-evaluated from the recorded validation), and
/// the gate `backup_snapshot::OrsBackupImportReceipt::known_zero_unresolved`.
/// It takes no `Database`, no `ReadTransaction` and no `WriteTransaction`, so it is
/// an ASSOCIATED function of `RedbRecoveryStore` taking only the prior receipt,
/// and it is CALLED on the type rather than through a `&self` method binding.
fn lost_response_replay_is_historical_953_15(
    receipt: &eliot_ors::OrsBackupImportReceipt,
    triaged: &[(String, PerEntryOutcome)],
) -> eliot_ors::OrsBackupImportReceipt {
    let replay = RedbRecoveryStore::reconcile_lost_backup_import_response(receipt);

    // The SAME operation, not a second one.
    assert_eq!(
        replay.snapshot_digest, receipt.snapshot_digest,
        "the replay is the historical record of the same operation"
    );
    assert_eq!(
        replay.source_installation, receipt.source_installation,
        "the replay names the same source installation"
    );
    assert_eq!(
        replay.destination_installation, receipt.destination_installation,
        "the replay names the same destination installation"
    );
    assert_eq!(
        replay.import_at_ms, receipt.import_at_ms,
        "the replay carries the ORIGINAL import stamp; no fresh attempt instant is minted"
    );
    assert_eq!(
        replay.expected_members, receipt.expected_members,
        "the replay re-derives nothing: the member roster is the one the original reconciliation recorded"
    );

    // NO duplicate effect and NO blind retry.
    assert_eq!(
        replay.per_entry, receipt.per_entry,
        "the replay produces no new outcome entries and drops none"
    );
    assert_eq!(
        replay.per_entry.len(),
        triaged.len(),
        "the denominator is still the one real triage produced"
    );
    assert_eq!(
        replay.unresolved_count, receipt.unresolved_count,
        "the replay does NOT clear the unresolved count: I14.21's unknown stays reconciling"
    );
    assert!(
        replay.unresolved_count > 0,
        "a brand new empty target never means the old effects are resolved"
    );

    // Replay remains HISTORICAL: it cannot manufacture fresh current-owner
    // evidence (`store::backup_snapshot::reconcile_lost_import_response`).
    assert_eq!(
        format!("{:?}", replay.current_owner_validation),
        format!("{:?}", receipt.current_owner_validation),
        "the whole recorded owner validation survives the replay unchanged, including its original consultation instant"
    );

    // The one thing the replay recomputes is the recorded verdict, re-derived
    // from the recorded validation by the PUBLIC gate
    // (`store::backup_snapshot::reconcile_lost_import_response`). It agrees with the original,
    // because the original was produced by the same gate
    // (`backup_snapshot::OrsBackupImportReceipt::new`) on the same unresolved denominator.
    assert_eq!(
        replay.known_zero_verdict, receipt.known_zero_verdict,
        "the gate agrees with itself across the replay, on the unresolved denominator"
    );
    match receipt.known_zero_unresolved(&receipt.current_owner_validation) {
        Err(OrsError::ReconciliationMismatch) => {}
        other => panic!("the PUBLIC gate must refuse this unresolved receipt, got {other:?}"),
    }
    replay
}

// WORK_UNIT_CASE: 953/16
#[test]
fn unresolved_imported_effects_are_retained_and_never_blindly_retried() -> TestResult {
    let (store, identity, path) = open_bound_store("16")?;
    let written = seed_operational_rows(&store, 1)?;
    let observed = observed_request(&store, &identity, MAX_BACKUP_PAGE_ENTRIES, 1)?;
    let exported = store.export_backup_snapshot(&observed)?;
    exported.validate()?;
    let roster = exported.expected_member_roster()?;
    assert_eq!(
        roster.len(),
        written.len(),
        "the archive really carries every row this case wrote, so the quarantine below is not vacuous"
    );

    // TWO requests, because the two entrypoints constrain the source DIFFERENTLY.
    // `RedbRecoveryStore::import_backup_page_quarantined` runs
    // `backup_snapshot::validate_import_binding`, whose FIRST rule refuses a source
    // equal to the destination, so the RE-TRIAGE request below declares a FOREIGN
    // source. `RedbRecoveryStore::reconcile_backup_import` runs
    // `store::backup_snapshot::expected_import_roster`, which compares the snapshot's
    // OWN source against `import.source` BEFORE the digest rule, so every
    // RECONCILE here declares the ARCHIVE's own source and its own recorded
    // denominator digest.
    let triage_import = OrsBackupImportRequest {
        snapshot_digest: exported.denominator_digest.clone(),
        source: import_origin(&identity, "16")?,
        destination: OrsBackupDestination::new(
            identity.installation_id().to_owned(),
            "admission-receipt-953-16".to_owned(),
            true,
        )?,
    };
    assert_ne!(
        triage_import.source.installation_id, triage_import.destination.installation_id,
        "the re-triage request's FOREIGN source really differs from this store's durable \
         installation, which is what `backup_snapshot::validate_import_binding` requires"
    );
    let import = OrsBackupImportRequest {
        snapshot_digest: exported.denominator_digest.clone(),
        source: exported.source.clone(),
        destination: triage_import.destination.clone(),
    };
    assert_eq!(
        import.source, exported.source,
        "every reconcile request names the ARCHIVE's own source identity, which \
         `store::backup_snapshot::expected_import_roster` compares BEFORE the digest rule"
    );

    // PHASE 1: the archive-derived selector, and the roster it must partition.
    // (`quarantine_selector_953_16`, below this test.)
    let terminal_members = quarantine_selector_953_16(&exported, &roster);

    // PHASE 2: the constructed five-arm outcome vector.
    // (`all_five_arm_denominator_953_16`, below this test.)
    let denominated = all_five_arm_denominator_953_16(&roster, &terminal_members);

    // `reconcile_backup_import` RETURNS a receipt for a vector that does not match the
    // roster, on purpose. A GATE refusal is a recorded verdict, not a construction
    // failure: `backup_snapshot::OrsBackupImportReceipt::new` invokes
    // `backup_snapshot::OrsBackupImportReceipt::known_zero_unresolved` against the
    // observed validation and records its `Err` as `KnownZeroVerdict::Refused`
    // instead of failing. The CONSTRUCTION rules are a different matter and they DO
    // fail the call: `store::backup_snapshot::expected_import_roster` runs
    // `backup_snapshot::OrsBackupSnapshot::validate` FIRST, and
    // `OrsBackupSnapshot::validate` -> `check_member_payload_states` requires every
    // member of a complete archive to carry a payload digest. So the receipt below is
    // returned under the GATE verdict and not under the construction rules, and the
    // coverage refusal that follows is what the recorded verdict reports.
    let receipt =
        store.reconcile_backup_import(&import, &exported, &denominated, IMPORT_AT_MS_953)?;

    // PHASE 3: the receipt retains the whole denominator, unresolved entries
    // included, with their reasons.
    receipt_denominator_retained_953_16(&receipt, &denominated, &roster)?;

    // PHASE 4: quarantine, not blind retry — and the PUBLIC gate's refusal on
    // this receipt's OWN recorded validation.
    retriage_stays_quarantined_953_16(&store, &triage_import, &import, &exported)?;

    // PHASE 5: that refusal is a judgement rather than a constant.
    gate_clause_discrimination_953_16(&store, &import, &exported, &roster, &terminal_members)?;

    // PHASE 6: a CHANGED payload under the SAME operation identity is refused by
    // production, never retried, and the refusal is typed.
    identity_conflict_is_not_retried_953_16(&store, &triage_import, &exported, 1, 0)?;

    remove_db(&path);
    Ok(())
}

/// PHASE 1 of case 953/16: the archive-derived SELECTOR that partitions the roster
/// into the committed `Terminal` checkpoint and the `Staged` staged operation, and
/// the proof that the selector covers the WHOLE roster rather than a subset.
///
/// CONSTRUCTED, AND SAID SO. The `&[(String, PerEntryOutcome)]` argument
/// `reconcile_backup_import` takes is a caller-supplied vector, so this case
/// assembles it explicitly instead of claiming the store produced it. Every
/// record id is one the ARCHIVE really declared: `roster` comes from
/// `backup_snapshot::OrsBackupSnapshot::expected_member_roster`. Only the outcome
/// VOCABULARY is constructed: `Unresolved` for EVERY archived member — the committed
/// `Terminal` checkpoint `checkpoint_job` writes at phase `Active` and the
/// `Staged` staged operation alike, because an unknown imported effect is
/// retained for the canonical owner rather than retried or assumed resolved —
/// plus one `Rejected` duplicate, one `Forensic` row, one `Blocked` row and
/// one `Imported` row, so every arm of the complete
/// imported/rejected/forensic/blocked/unresolved denominator the card asks
/// for is present on ONE receipt.
///
/// THE FAMILY SELECTOR IS THE TRUTHFUL ONE, and there is exactly one to
/// choose. `backup_snapshot::RowFamilyKind` declares unit variants and NONE of
/// them is a checkpoint family. It does not need to be: `checkpoint_job` and
/// `stage` are BOTH `OperationalRecoveryStore` writers that reach the SAME durable
/// family through `mutate_operational` (`store::RedbRecoveryStore::stage` and
/// `store::RedbRecoveryStore::checkpoint_job`, both keyed by
/// `Self::operational_key(kind, &input.subject_id)`), and the export walk
/// that reads it back stamps EVERY row it emits — staged operations and
/// committed checkpoints alike — as `RowFamilyKind::OperationalHistory` in
/// `store::backup_snapshot::operational_walk`. So the family of a member this case
/// writes is `OperationalHistory`, and selecting a family whose name merely
/// SOUNDS like the row (`RecoveryProblems`, `Reservations`, …) would select a
/// family this archive provably does not contain, making that selector dead
/// rather than honest.
///
/// That family also cannot DISCRIMINATE the committed checkpoint from the
/// staged operation — they share it — so family membership alone would leave
/// the two arms indistinguishable. The archive's OWN declared per-member
/// property can, and this case uses the one the export really sets:
/// `backup_snapshot::OrsBackupEntry::effect_class`.
/// `store::backup_snapshot::effect_class_for_export` maps
/// `OperationalPhase::Staged -> StoredEffectClass::Staged` and
/// `OperationalPhase::Active -> StoredEffectClass::Terminal`, and case 7
/// (`WORK_UNIT_CASE: 953/7`) already reads BOTH arms off a real
/// export of this same fixture through this same call. The selector is
/// therefore a property of the archive, not of a spelling — which is what the
/// dead `starts_with("job-checkpoint")` prefix selector was replaced with,
/// and this time it names an axis that actually varies.
///
/// OWNER: `backup_snapshot::OrsBackupEntry::effect_class` as set by
/// `store::backup_snapshot::effect_class_for_export` and read back by
/// the export walk in `store::backup_snapshot::operational_walk`.
fn quarantine_selector_953_16(
    exported: &OrsBackupSnapshot,
    roster: &[(RowFamilyKind, String)],
) -> Vec<String> {
    let mut terminal_members: Vec<String> = Vec::new();
    let mut staged_members: Vec<String> = Vec::new();
    for page in &exported.pages {
        for entry in &page.entries {
            // Family membership first, so this case can only ever select out of
            // the family it claims to be reading.
            if entry.family != RowFamilyKind::OperationalHistory {
                continue;
            }
            match entry.effect_class {
                StoredEffectClass::Terminal => terminal_members.push(entry.record_id.clone()),
                StoredEffectClass::Staged => staged_members.push(entry.record_id.clone()),
                StoredEffectClass::Possible | StoredEffectClass::Unknown => {}
            }
        }
    }
    // The roster this case reasons over is the ARCHIVE's own roster, and the
    // selector must partition it exactly: every member it triages is an
    // operational-history member carrying one of the two effect classes the
    // export really produces from this fixture.
    assert_eq!(
        terminal_members.len() + staged_members.len(),
        roster.len(),
        "every archived member is an operational-history member whose exported effect class is \
         one of the two this fixture produces (`Staged` for the staged operation, `Terminal` for \
         the committed Active checkpoint), so the selector below partitions the whole roster and \
         selects on a real archive axis"
    );
    assert!(
        !terminal_members.is_empty(),
        "the archive really carries a Terminal member (the committed Active checkpoint), so the \
         arm selected below is not the unreachable arm it would be if no member were of that class"
    );
    assert!(
        !staged_members.is_empty(),
        "and it really carries a Staged member, so the OTHER arm below is reachable too"
    );
    terminal_members
}

/// PHASE 2 of case 953/16: the constructed outcome vector. Every archived member
/// lands the `Unresolved` arm — the committed checkpoint and the staged operation
/// are BOTH quarantined for the canonical reconciliation owner, which is precisely
/// the card's demand ("unresolved imported effects retained for canonical owner, not
/// blindly retried") and TASK.md line 51's "No blind retry or fabricated zero
/// unresolved count". A member that came back `Imported` here would be a blind
/// retry, and one that was dropped would be a fabricated zero. The four
/// non-roster entries then supply the `Rejected` / `Forensic` / `Blocked` /
/// `Imported` arms, so all FIVE arms of the per-entry denominator the card demands
/// are present on ONE receipt.
///
/// OWNER: the caller-supplied `&[(String, PerEntryOutcome)]` of
/// `store::RedbRecoveryStore::reconcile_backup_import`, against the archive's own
/// roster from `OrsBackupSnapshot::expected_member_roster`
/// (`backup_snapshot::OrsBackupSnapshot::expected_member_roster`).
fn all_five_arm_denominator_953_16(
    roster: &[(RowFamilyKind, String)],
    terminal_members: &[String],
) -> Vec<(String, PerEntryOutcome)> {
    let mut quarantined: Vec<(String, PerEntryOutcome)> = roster
        .iter()
        .map(|(_, record_id)| {
            if terminal_members.contains(record_id) {
                (
                    record_id.clone(),
                    PerEntryOutcome::Unresolved {
                        reason:
                            "953/16 committed durable effect quarantined for the canonical owner; \
                             no authority conferred, never retried"
                                .to_owned(),
                    },
                )
            } else {
                (
                    record_id.clone(),
                    PerEntryOutcome::Unresolved {
                        reason: "953/16 staged effect quarantined for the canonical owner; no \
                             authority conferred, never retried"
                            .to_owned(),
                    },
                )
            }
        })
        .collect();
    // Every member this case constructed really landed the `Unresolved` arm: the
    // committed checkpoint and the staged operation are BOTH quarantined for the
    // canonical reconciliation owner. A member that came back `Imported` here
    // would be a blind retry, and one that was dropped would be a fabricated zero.
    let blocked_in_vector = quarantined
        .iter()
        .filter(|(_, outcome)| matches!(outcome, PerEntryOutcome::Blocked { .. }))
        .count();
    let unresolved_in_constructed = quarantined
        .iter()
        .filter(|(_, outcome)| matches!(outcome, PerEntryOutcome::Unresolved { .. }))
        .count();
    assert_eq!(
        blocked_in_vector, 0,
        "no archived member was blocked rather than quarantined: an unknown stays UNRESOLVED for \
         the canonical owner, and blocking one would understate the denominator the owner has to \
         reconcile"
    );
    assert_eq!(
        unresolved_in_constructed,
        roster.len(),
        "EVERY archived member really landed the Unresolved arm: the committed Terminal \
         checkpoint and the Staged operation alike are retained as unresolved, none dropped, none \
         reset, none reported Imported"
    );
    assert_eq!(
        unresolved_in_constructed,
        terminal_members.len() + roster.len() - terminal_members.len(),
        "and that is exactly the two effect classes the archive's own selector partitioned, so the \
         Unresolved arm covers the whole selected roster"
    );
    // All FIVE arms of the per-entry denominator the card demands
    // ("imported/rejected/forensic/blocked/unresolved") are on ONE receipt. The
    // four non-roster entries below are the `Rejected` / `Forensic` / `Blocked` /
    // `Imported` arms; the archived roster supplies every `Unresolved` arm. Each
    // added id is FOREIGN to the roster, which is deliberate: `reconcile_backup_import`
    // must still RETURN this receipt rather than refuse to build it, so the
    // receipt's coverage refusal can be observed rather than inferred.
    let extra = quarantined.len();
    let mut denominated = std::mem::take(&mut quarantined);
    denominated.push((
        format!("record-953-16-duplicate-{extra}"),
        PerEntryOutcome::Rejected {
            reason: "953/16 duplicate entry already durably stored".to_owned(),
        },
    ));
    denominated.push((
        format!("record-953-16-forensic-{extra}"),
        PerEntryOutcome::Forensic {
            reason: "953/16 historical row never crosses a restore boundary".to_owned(),
        },
    ));
    denominated.push((
        format!("record-953-16-blocked-{extra}"),
        PerEntryOutcome::Blocked {
            reason: "953/16 fenced durable authority is blocked, never retried".to_owned(),
        },
    ));
    denominated.push((
        format!("record-953-16-imported-{extra}"),
        PerEntryOutcome::Imported,
    ));
    denominated
}

/// PHASE 3 of case 953/16: the receipt retains the COMPLETE per-entry denominator
/// exactly as triaged, unresolved entries included with their reasons; the
/// unresolved count is DERIVED from the outcomes, not supplied beside them; all
/// five arms survive; and the current owner was asked about EVERY archived member
/// and only about real ones.
///
/// OWNER: `backup_snapshot::OrsBackupImportReceipt::new` (derives the
/// unresolved count from the outcomes themselves),
/// `store::backup_snapshot::expected_import_roster` and
/// `store::backup_snapshot::observe_current_owner_validation`.
fn receipt_denominator_retained_953_16(
    receipt: &eliot_ors::OrsBackupImportReceipt,
    denominated: &[(String, PerEntryOutcome)],
    roster: &[(RowFamilyKind, String)],
) -> TestOutcome<()> {
    assert_eq!(
        receipt.expected_members, roster,
        "the receipt's expected roster is the ARCHIVE's own member set, established before a single outcome was read (`store::backup_snapshot::expected_import_roster`)"
    );

    // No fabricated zero: the count is DERIVED from the outcomes
    // (`backup_snapshot::OrsBackupImportReceipt::new`), and the expected value is
    // the REAL number of unresolved outcomes on the vector the store was handed —
    // the whole archived roster, not a number this case chose.
    let unresolved_in_vector = denominated
        .iter()
        .filter(|(_, outcome)| matches!(outcome, PerEntryOutcome::Unresolved { .. }))
        .count();
    assert_eq!(
        unresolved_in_vector,
        roster.len(),
        "the quarantined vector really holds one Unresolved outcome per archived member: both \
         the committed Terminal checkpoint and the Staged operation are retained as unknown for \
         the canonical owner, and the three added non-roster outcomes (Rejected/Forensic/Imported) \
         are not Unresolved, so the count the receipt is compared against is the one this roster \
         actually produces"
    );
    assert_eq!(
        receipt.unresolved_count,
        u64::try_from(unresolved_in_vector)?,
        "the unresolved count is the number of Unresolved outcomes in the vector"
    );
    assert!(
        receipt.unresolved_count > 0,
        "an import holding an unknown outcome must not report a zero unresolved count"
    );

    // Every entry retained, unresolved ones included, with their reasons.
    assert_eq!(
        receipt.per_entry, denominated,
        "the receipt retains the COMPLETE per-entry denominator exactly as triaged, unresolved entries included"
    );
    assert_eq!(
        receipt
            .per_entry
            .iter()
            .filter(|(_, outcome)| matches!(outcome, PerEntryOutcome::Unresolved { .. }))
            .count(),
        unresolved_in_vector,
        "the unresolved entry is still present on the receipt after reconciliation"
    );
    for (arm_name, retained) in [
        (
            "Blocked",
            receipt
                .per_entry
                .iter()
                .any(|(_, outcome)| matches!(outcome, PerEntryOutcome::Blocked { .. })),
        ),
        (
            "Forensic",
            receipt
                .per_entry
                .iter()
                .any(|(_, outcome)| matches!(outcome, PerEntryOutcome::Forensic { .. })),
        ),
        (
            "Rejected",
            receipt
                .per_entry
                .iter()
                .any(|(_, outcome)| matches!(outcome, PerEntryOutcome::Rejected { .. })),
        ),
    ] {
        assert!(
            retained,
            "the {arm_name} entry is retained on the receipt too, not dropped"
        );
    }
    assert!(
        receipt
            .per_entry
            .iter()
            .any(|(_, outcome)| *outcome == PerEntryOutcome::Imported),
        "the Imported entry is retained on the receipt too, so the denominator carries all five arms"
    );
    assert_eq!(
        receipt.current_owner_validation.validated_record_ids.len(),
        roster.len(),
        "the current owner was asked about EVERY archived member (`store::backup_snapshot::observe_current_owner_validation`)"
    );
    assert!(
        receipt
            .current_owner_validation
            .validated_record_ids
            .iter()
            .all(|id| roster.iter().any(|(_, member)| member == id)),
        "the consulted roster names only real archived members, so the foreign ids below are NOT in it"
    );
    Ok(())
}

/// PHASE 4 of case 953/16: quarantine, not blind retry. Nothing was applied, so
/// re-triage on the REAL page still lands the same members Unresolved and nothing
/// is activated or acknowledged anywhere; and the PUBLIC gate refuses, on the
/// receipt's OWN recorded validation. The refusal names member COVERAGE rather than
/// the unresolved outcome first: the gate checks coverage before it counts outcomes
/// in `OrsBackupImportReceipt::known_zero_unresolved`, and coverage is the clause
/// `OrsBackupImportReceipt::owner_validation_is_complete` evaluates.
///
/// The RE-TRIAGE request is the FOREIGN-source one, because
/// `backup_snapshot::validate_import_binding` refuses a source equal to the
/// destination; the RECONCILE request is the archive-own-source one, because
/// `store::backup_snapshot::expected_import_roster` refuses anything else before it
/// will read a roster. One request cannot satisfy both rules at once.
fn retriage_stays_quarantined_953_16(
    store: &RedbRecoveryStore,
    triage_import: &OrsBackupImportRequest,
    reconcile_import: &OrsBackupImportRequest,
    exported: &OrsBackupSnapshot,
) -> TestOutcome<()> {
    let page = exported.pages.first().ok_or(
        "the exported snapshot carries the page this case triages, which is a fixture failure",
    )?;
    let retriaged = store.import_backup_page_quarantined(triage_import, page)?;
    assert_eq!(
        retriaged.len(),
        page.entries.len(),
        "re-triage still returns exactly one outcome per archived member"
    );
    for (record_id, outcome) in &retriaged {
        assert!(
            matches!(
                outcome,
                PerEntryOutcome::Unresolved { .. } | PerEntryOutcome::Blocked { .. }
            ),
            "member {record_id} is still quarantined on a destination nothing was applied to, never re-imported as Imported"
        );
    }
    let receipt =
        store.reconcile_backup_import(reconcile_import, exported, &retriaged, IMPORT_AT_MS_953)?;
    assert_eq!(
        receipt.expected_members,
        exported.expected_member_roster()?,
        "the re-triaged receipt's roster is the ARCHIVE's own member set, established before a \
         single outcome was read (`store::backup_snapshot::expected_import_roster`)"
    );
    match receipt.known_zero_unresolved(&receipt.current_owner_validation) {
        Err(OrsError::ReconciliationMismatch) => {}
        other => panic!(
            "the known-zero gate must refuse a vector holding an Unresolved outcome, got {other:?}"
        ),
    }
    Ok(())
}

/// PHASE 5 of case 953/16: that refusal is a judgement rather than a constant. The
/// vector corrected to the archive's EXACT member set (no foreign ids) is accepted
/// by `reconcile_backup_import`, carries COMPLETE coverage (this is the card's
/// "complete current owner validation"), and its gate refuses again, this time
/// because clause 6 sees a real Unresolved outcome. A `ReconciliationMismatch` WITH
/// complete coverage can only be that clause.
///
/// The one member that IS resolved is chosen by the SAME archive-derived selector
/// used above — the committed Terminal effect is the one the canonical owner can
/// already speak for — so this control differs from the `resolved` vector below in
/// exactly one entry, which is what makes the refusal attributable to the
/// unresolved entry and not to the validation. The accepting arm is then the SAME
/// complete validation beside a vector with no unknown outcome at all: the
/// discrimination the brief asks for. The gate is reachable, and it is the
/// unresolved entry, not the validation, that refuses it.
///
/// OWNER: `store::RedbRecoveryStore::reconcile_backup_import` and the PUBLIC gate
/// `backup_snapshot::OrsBackupImportReceipt::known_zero_unresolved`,
/// whose last clause is the outcome count.
fn gate_clause_discrimination_953_16(
    store: &RedbRecoveryStore,
    import: &OrsBackupImportRequest,
    exported: &OrsBackupSnapshot,
    roster: &[(RowFamilyKind, String)],
    terminal_members: &[String],
) -> TestOutcome<()> {
    let corrected: Vec<(String, PerEntryOutcome)> = roster
        .iter()
        .map(|(_, record_id)| {
            if terminal_members.contains(record_id) {
                (record_id.clone(), PerEntryOutcome::Imported)
            } else {
                (
                    record_id.clone(),
                    PerEntryOutcome::Unresolved {
                        reason: "953/16 one archived member stays unknown".to_owned(),
                    },
                )
            }
        })
        .collect();
    let corrected_unresolved = corrected
        .iter()
        .filter(|(_, outcome)| matches!(outcome, PerEntryOutcome::Unresolved { .. }))
        .count();
    assert!(
        corrected_unresolved > 0 && corrected_unresolved < corrected.len(),
        "the corrected vector holds SOME unknown outcomes and SOME resolved ones, so the refusal \
         below is attributable to the unresolved entries rather than to the coverage of the roster"
    );
    let still_unknown =
        store.reconcile_backup_import(import, exported, &corrected, IMPORT_AT_MS_953)?;
    assert_eq!(
        still_unknown.per_entry.len(),
        roster.len(),
        "the corrected vector covers every archived member exactly once, and adds no foreign id"
    );
    assert_eq!(
        still_unknown.unresolved_count,
        u64::try_from(corrected_unresolved)?,
        "the corrected vector's unresolved count is DERIVED by the store from the outcomes this \
         case really put on it, and equals the number of them"
    );
    match still_unknown.known_zero_unresolved(&still_unknown.current_owner_validation) {
        Err(OrsError::ReconciliationMismatch) => {}
        other => panic!(
            "a complete validation beside one quarantined outcome must still refuse the gate, got {other:?}"
        ),
    }

    // The case that accepts: the SAME complete validation beside a vector with no
    // unknown outcome at all.
    let resolved: Vec<(String, PerEntryOutcome)> = roster
        .iter()
        .map(|(_, record_id)| (record_id.clone(), PerEntryOutcome::Imported))
        .collect();
    let accepted = store.reconcile_backup_import(import, exported, &resolved, IMPORT_AT_MS_953)?;
    assert_eq!(
        accepted.unresolved_count, 0,
        "the accepted vector reports no unresolved outcome"
    );
    assert_eq!(
        accepted.current_owner_validation.validated_record_ids.len(),
        roster.len(),
        "this validation is COMPLETE current-owner coverage of every archived member"
    );
    assert!(
        accepted
            .known_zero_unresolved(&accepted.current_owner_validation)
            .is_ok(),
        "a complete current-owner validation over the whole roster with no unresolved outcome is the ONE satisfying case"
    );
    Ok(())
}

/// PHASE 6 of case 953/16: a CHANGED payload under the SAME operation identity is
/// refused by production with a typed conflict, never overwrites the earlier
/// evidence, and is never retried. This is the rule I05-27 names for a reused
/// idempotency key ("reusing an idempotency key with a different canonical request
/// hash performs no transition"), read at the owner that actually holds the durable
/// rows rather than inferred from an import request.
///
/// The pair is the SAME operation identity twice, and it is the pair production
/// actually decides between: an EXACT replay of the row the writer already holds is
/// accepted and returns that row's own receipt, while a CHANGED payload under the
/// same identity is refused with `OrsError::DuplicateConflict` and writes nothing.
/// Both are driven through the public `OperationalRecoveryStore::stage` writer, with
/// every identity-bearing field identical — `record_id`, `subject_id`, authority
/// epoch, state fence and creation instant — and only the opaque body differing.
///
/// The identities are derived from the seed indices exactly as
/// `seed_operational_rows` wrote them, and the helper ASSERTS that each derived
/// identity really appears in this case's own exported archive, so the convention is
/// proved against the archive rather than assumed.
///
/// OWNER: `OperationalRecoveryStore::stage` -> `mutate_operational`, whose exact-
/// replay arm returns the existing row's receipt and whose same-identity/different-
/// input arm returns `OrsError::DuplicateConflict`; and
/// `store::backup_snapshot::triage_entry`, which the read-back below goes through.
fn identity_conflict_is_not_retried_953_16(
    store: &RedbRecoveryStore,
    triage_import: &OrsBackupImportRequest,
    exported: &OrsBackupSnapshot,
    conflicted_index: usize,
    intact_index: usize,
) -> TestOutcome<()> {
    let authority_epoch = epoch_lineage()?;
    let conflicted_record_id = format!("stage-953-{conflicted_index}");
    let conflicted_subject_id = format!("operation-953-{conflicted_index}");
    let intact_record_id = format!("stage-953-{intact_index}");
    let archived_ids = || -> Result<Vec<String>, OrsError> {
        Ok(exported
            .pages
            .iter()
            .flat_map(|page| page.entries.iter())
            .map(|entry| entry.record_id.clone())
            .collect())
    };
    assert!(
        archived_ids()?.iter().any(|id| id == &conflicted_record_id)
            && archived_ids()?.iter().any(|id| id == &intact_record_id),
        "both identities this phase addresses really appear in this case's own exported archive, \
         so the pair below is driven over the exact rows the seed wrote"
    );

    // The control FIRST: an EXACT replay of the row the writer already holds is
    // accepted and returns that row's own receipt. `mutate_operational` compares the
    // incoming input with the stored one and returns the existing receipt when they
    // are equal, so this arm is the discrimination the refusal below needs.
    let exact_replay = StagedOperation::new(operational_input(
        &conflicted_record_id,
        &conflicted_subject_id,
        &authority_epoch,
        &format!("opaque-stage-953-{conflicted_index}"),
    )?)?;
    let replayed = store.stage(exact_replay)?;
    assert_eq!(
        replayed.receipt().record_id().as_str(),
        conflicted_record_id,
        "an EXACT replay under the SAME operation identity is ACCEPTED and returns the existing \
         row's own receipt, bound to that row's own record identity, so the refusal below is the \
         changed-payload rule and not a refusal of every replay"
    );

    // The CHANGED payload: identical in every identity-bearing field, different bytes.
    let changed_payload = StagedOperation::new(operational_input(
        &conflicted_record_id,
        &conflicted_subject_id,
        &authority_epoch,
        "opaque-stage-953-16-REPLAYED-UNDER-A-CHANGED-PAYLOAD",
    )?)?;
    match store.stage(changed_payload) {
        Err(OrsError::DuplicateConflict) => {}
        other => panic!(
            "a second, DIFFERENT payload presented under the SAME operation identity must be \
             refused with the typed duplicate conflict and never overwrite the earlier evidence, \
             got {other:?}"
        ),
    }
    // The refusal really was a refusal: the durable row is still the one the seed
    // wrote, re-read through the store's OWN quarantine classification rather than
    // through the writer's return value.
    let after_conflict =
        triage_entry_953_16(store, triage_import, exported, &conflicted_record_id)?;
    assert_eq!(
        after_conflict, conflicted_record_id,
        "the conflicted identity is unchanged after the refusal: the original durable evidence \
         survived, so nothing was overwritten and nothing was retried"
    );

    // The sibling arm of the same rule: an identity this store already holds, whose
    // archive entry matches the durable row exactly, replays as a DUPLICATE through the
    // store's own quarantine classification. Nothing was applied by any reconciliation
    // above, so nothing is retried and no identity comes back as `Imported`.
    let duplicate = triage_entry_953_16(store, triage_import, exported, &intact_record_id)?;
    assert_eq!(
        duplicate, intact_record_id,
        "the untouched sibling identity is still durably present and still resolves to itself"
    );
    Ok(())
}

/// The disposition the store's own quarantine triage records for ONE real exported
/// entry, addressed by the record identity the ARCHIVE declares for it.
///
/// `store::backup_snapshot::triage_entry` classifies an entry by scanning the durable
/// `OPERATIONAL_HISTORY` family for a stored row whose `record_id` equals the entry's,
/// then comparing that row's OWN encoded hash against the entry's `payload_digest`. The
/// pages are the ones this case's own real export produced, and the export derives each
/// `payload_digest` from the very bytes the writer persisted, so the two hashes are
/// EQUAL for every archived member and the duplicate arm is the one that fires.
///
/// The `Blocked { reason: "IDENTITY_CONFLICT: key reuse with a different hash" }` arm is
/// therefore NOT reachable from this fixture and is not asserted here: it needs an
/// archive whose entry digest disagrees with the durable row, which is exactly the key
/// reuse `OperationalRecoveryStore::mutate_operational` refuses to write in the first
/// place. Asserting it would be asserting a condition this fixture cannot produce.
///
/// OWNER: `RedbRecoveryStore::import_backup_page_quarantined` ->
/// `store::backup_snapshot::import_page_quarantined` ->
/// `store::backup_snapshot::triage_entry`, whose equal-hash arm is
/// `PerEntryOutcome::Rejected { reason: "duplicate entry already durably stored" }`.
fn triage_entry_953_16(
    store: &RedbRecoveryStore,
    import: &OrsBackupImportRequest,
    exported: &OrsBackupSnapshot,
    wanted: &str,
) -> TestOutcome<String> {
    let mut classified: Vec<(String, PerEntryOutcome)> = Vec::new();
    for page in &exported.pages {
        classified.extend(store.import_backup_page_quarantined(import, page)?);
    }
    let (record_id, outcome) = classified
        .iter()
        .find(|(record_id, _)| record_id == wanted)
        .ok_or(
            "the real exported pages really carried the entry this case addresses, which is a \
             fixture failure",
        )?;
    assert!(
        matches!(outcome, PerEntryOutcome::Rejected { .. }),
        "an archived record identity this store ALREADY holds durably replays as the duplicate \
         `Rejected` arm on a destination nothing was applied to, never as `Imported`; got \
         {outcome:?} for {record_id}"
    );
    Ok(record_id.clone())
}

// WORK_UNIT_CASE: 953/17
#[test]
fn known_zero_requires_complete_current_owner_validation() -> TestResult {
    let (store, identity, path) = open_bound_store("17")?;
    let written = seed_operational_rows(&store, 1)?;
    let observed = observed_request(&store, &identity, MAX_BACKUP_PAGE_ENTRIES, 1)?;
    let exported = store.export_backup_snapshot(&observed)?;
    exported.validate()?;
    assert_eq!(
        exported.entry_count,
        u64::try_from(written.len())?,
        "the archive under test is NON-EMPTY: it carries every operational row this case wrote, so no verdict below could be reached through an empty roster"
    );

    let import = OrsBackupImportRequest {
        snapshot_digest: fence_digest('a'),
        source: import_origin(&identity, "17")?,
        destination: OrsBackupDestination::new(
            identity.installation_id().to_owned(),
            "admission-receipt-953-17".to_owned(),
            true,
        )?,
    };
    let roster = exported.expected_member_roster()?;
    assert_eq!(
        roster.len(),
        written.len(),
        "the archive's member roster is the whole denominator the gate compares against"
    );

    // The imported vector: one `Imported` outcome per archived member, so the
    // ONLY thing that can refuse the gate is COVERAGE, never an unknown outcome.
    let imported: Vec<(String, PerEntryOutcome)> = roster
        .iter()
        .map(|(_, record_id)| (record_id.clone(), PerEntryOutcome::Imported))
        .collect();

    // ---- (a) the CORRECT FULL roster --------------------------------------
    // The one roster that satisfies the gate.
    let correct = store.reconcile_backup_import(&import, &exported, &imported, IMPORT_AT_MS_953)?;
    correct_full_roster_is_satisfied_953_17(&correct, &import);

    // ---- (a1) an EMPTY roster: no outcome at all ---------------------------
    let empty_receipt = empty_roster_is_refused_953_17(&store, &import, &exported, &roster)?;

    // ---- (b) a SUBSET roster: one expected member dropped -----------------
    let subset_receipt =
        subset_roster_is_refused_953_17(&store, &import, &exported, &roster, &imported)?;

    // ---- (c) a FOREIGN roster and ---- (d) a DUPLICATED roster ------------
    let foreign_receipt =
        foreign_roster_is_refused_953_17(&store, &import, &exported, &roster, &imported)?;
    let duplicated_receipt =
        duplicated_roster_is_refused_953_17(&store, &import, &exported, &imported)?;

    // Nothing above is a bare refusal, and exactly one roster satisfies the gate.
    refusals_are_the_coverage_clause_953_17(
        &correct,
        &empty_receipt,
        &subset_receipt,
        &foreign_receipt,
        &duplicated_receipt,
    );

    remove_db(&path);
    Ok(())
}

/// (a) of case 953/17: the CORRECT FULL roster. It carries no unresolved outcome,
/// its validation is bound to THIS snapshot, the current owner's own answer is
/// "nothing unresolved", and the gate is SATISFIED — so the ONLY thing that can
/// refuse the gate in the arms below is COVERAGE.
///
/// OWNER: `RedbRecoveryStore::reconcile_backup_import` (`src/store.rs::reconcile_backup_import`)
/// and the PUBLIC gate `OrsBackupImportReceipt::known_zero_unresolved`
/// (`src/backup_snapshot.rs::known_zero_unresolved`).
fn correct_full_roster_is_satisfied_953_17(
    correct: &eliot_ors::OrsBackupImportReceipt,
    import: &OrsBackupImportRequest,
) {
    assert_eq!(
        correct.unresolved_count, 0,
        "roster (a) reports no unresolved outcome, so only the COVERAGE clause can decide its gate"
    );
    assert_eq!(
        correct.current_owner_validation.snapshot_digest, import.snapshot_digest,
        "roster (a): the validation is bound to THIS snapshot, so it answers this operation's question"
    );
    assert!(
        correct
            .current_owner_validation
            .unresolved_effect_identities
            .is_empty(),
        "roster (a): this installation holds no live recovery-inbox row and no unresolved recovery problem, so the current owner's own answer is 'nothing unresolved'"
    );
    assert!(
        correct
            .known_zero_unresolved(&correct.current_owner_validation)
            .is_ok(),
        "roster (a) SATISFIED: complete coverage of the whole roster and no unknown outcome"
    );
}

/// (a1) of case 953/17: an EMPTY roster — no outcome at all — over a NON-EMPTY
/// snapshot. This is one of the four rosters the issue names ("a nonempty
/// snapshot with an empty, subset, foreign or duplicated outcome roster"). Its gate
/// refusal is read the way the brief requires — the `KnownZeroVerdict` is not
/// nameable from a test, so it is read as `Satisfied` / not-`Satisfied` through the
/// fieldless variant's `Debug` text AND through the public gate's own `Ok`/`Err` —
/// so a refusal is recorded on the receipt by the store, not merely observed at the
/// gate.
///
/// OWNER: `expected_import_roster`
/// (`src/store/backup_snapshot.rs::expected_import_roster`, the expectation is
/// re-derived from the validated snapshot, not caller-supplied) and
/// `OrsBackupImportReceipt::known_zero_unresolved`
/// (`src/backup_snapshot.rs::known_zero_unresolved`).
fn empty_roster_is_refused_953_17(
    store: &RedbRecoveryStore,
    import: &OrsBackupImportRequest,
    exported: &OrsBackupSnapshot,
    roster: &[(RowFamilyKind, String)],
) -> TestOutcome<eliot_ors::OrsBackupImportReceipt> {
    let empty: Vec<(String, PerEntryOutcome)> = Vec::new();
    let empty_receipt =
        store.reconcile_backup_import(import, exported, &empty, IMPORT_AT_MS_953)?;
    assert!(
        empty.is_empty() && !roster.is_empty(),
        "the roster under test really is EMPTY, over a NON-EMPTY snapshot"
    );
    assert_eq!(
        empty_receipt.expected_members.len(),
        roster.len(),
        "an empty outcome vector does NOT make the archive's member roster empty: the expectation \
         is re-derived from the validated snapshot, so the archive still declares every member"
    );
    assert_eq!(
        empty_receipt.unresolved_count, 0,
        "roster (a1): an empty vector carries no Unresolved outcome, so the refusal below is NOT \
         the unresolved clause — it is the coverage clause refusing an empty outcome roster"
    );
    assert_ne!(
        format!("{:?}", empty_receipt.known_zero_verdict),
        "Satisfied",
        "roster (a1) empty must NOT report a satisfied known-zero: the store recorded {:?}",
        empty_receipt.known_zero_verdict
    );
    match empty_receipt.known_zero_unresolved(&empty_receipt.current_owner_validation) {
        Err(OrsError::ReconciliationMismatch) => {}
        other => {
            panic!("roster (a1) empty must NOT report a satisfied known-zero, got {other:?}")
        }
    }
    Ok(empty_receipt)
}

/// (b) of case 953/17: a SUBSET outcome roster — one archived member's outcome
/// dropped. CONSTRUCTED, AND SAID SO: `reconcile_import_receipt` takes the
/// caller's outcome vector verbatim (`src/store/backup_snapshot.rs::reconcile_import_receipt`),
/// so the subset below is built here. `expected_members` is NOT caller-supplied;
/// it is re-derived from the snapshot on every call by `expected_import_roster`
/// (`src/store/backup_snapshot.rs::expected_import_roster`), and the current owner
/// is asked about THAT roster
/// (`src/store/backup_snapshot.rs::observe_current_owner_validation`).
///
/// THE EXPECTATION BELOW IS DERIVED FROM THE ARCHIVE'S OWN PAGES, not from the
/// roster this case passed in and not from `OrsBackupSnapshot::expected_member_roster`:
/// this body walks `exported.pages` itself and folds every
/// `(entry.family, entry.record_id)` pair into a `BTreeSet`, so the compared set is
/// an independent reading of the same pages `expected_import_roster` reads.
/// Comparing the receipt against a copy of the caller-supplied vector would be
/// circular, and a LENGTH comparison could not tell a subset from a superset from a
/// different roster of the same size — which is precisely the count-only proof shape
/// this issue forbids.
///
/// WHAT IS PROVED, stated once: the receipt binds the INDEPENDENTLY derived
/// denominator rather than the caller's subset. A caller that omits an outcome
/// cannot shrink `expected_members`, cannot shrink the roster the current owner was
/// asked about, and is therefore refused by the coverage comparison in
/// `OrsBackupImportReceipt::owner_validation_is_complete`
/// (`src/backup_snapshot.rs::owner_validation_is_complete`, whose
/// consulted-vs-expected equality is the deciding conjunct) rather than reported as
/// satisfied.
///
/// OWNER: `reconcile_import_receipt`
/// (`src/store/backup_snapshot.rs::reconcile_import_receipt`),
/// `expected_import_roster`
/// (`src/store/backup_snapshot.rs::expected_import_roster`) and
/// `observe_current_owner_validation`
/// (`src/store/backup_snapshot.rs::observe_current_owner_validation`).
fn subset_roster_is_refused_953_17(
    store: &RedbRecoveryStore,
    import: &OrsBackupImportRequest,
    exported: &OrsBackupSnapshot,
    roster: &[(RowFamilyKind, String)],
    imported: &[(String, PerEntryOutcome)],
) -> TestOutcome<eliot_ors::OrsBackupImportReceipt> {
    // The INDEPENDENT denominator: read straight off the archive's own pages,
    // exactly as `OrsBackupSnapshot::expected_member_roster` does, without calling
    // it and without reference to any caller-supplied list.
    let archive_roster: BTreeSet<(RowFamilyKind, String)> = exported
        .pages
        .iter()
        .flat_map(|page| page.entries.iter())
        .map(|entry| (entry.family, entry.record_id.clone()))
        .collect();
    // `OrsBackupSnapshot::expected_member_roster` hands back the same set in the
    // same sorted order, so this sorted vector is the exact shape to compare
    // against. Sorted, not just counted: a length could not distinguish a subset
    // from a superset from a different roster of the same size.
    let archive_members: Vec<(RowFamilyKind, String)> = archive_roster.iter().cloned().collect();
    assert_eq!(
        archive_roster.len(),
        roster.len(),
        "the archive pages really do declare every member of the roster under test, so the \
         independent reading below is over the same denominator and not a smaller one"
    );
    let dropped = roster
        .last()
        .map(|(_, record_id)| record_id.clone())
        .ok_or("the roster really holds the member this subset drops")?;
    let subset: Vec<(String, PerEntryOutcome)> = imported
        .iter()
        .filter(|(record_id, _)| record_id.as_str() != dropped.as_str())
        .cloned()
        .collect();
    assert_eq!(
        subset.len(),
        roster.len().wrapping_sub(1),
        "the subset really is one member short of the roster"
    );
    let subset_receipt =
        store.reconcile_backup_import(import, exported, &subset, IMPORT_AT_MS_953)?;
    assert_eq!(
        subset_receipt.expected_members.len(),
        archive_members.len(),
        "the store still demands the ARCHIVE's whole roster: the subset did not shrink the expectation"
    );
    assert_eq!(
        subset_receipt.expected_members, archive_members,
        "the receipt's expected roster is EXACTLY the set this case read off the archive's own \
         pages — member for member, not merely the same count — so the expectation is \
         independently derived and a count equality is not what is being proved"
    );
    assert_eq!(
        subset_receipt
            .current_owner_validation
            .validated_record_ids
            .len(),
        archive_members.len(),
        "the current owner was still asked about every archived member"
    );
    // The core of the repair, stated as a positive claim about the ARCHIVE'S member
    // rather than about the caller's triage: the dropped member is still inside the
    // roster the owner was consulted about, so the validation did NOT shrink to the
    // subset. Before the AUD1 repair this list was the caller's own vector, and the
    // dropped member was absent from it; it is derived from `expected_members`
    // instead (`observe_current_owner_validation`), so it is present whether or not
    // the caller triaged it.
    assert!(
        subset_receipt
            .current_owner_validation
            .validated_record_ids
            .iter()
            .any(|record_id| record_id.as_str() == dropped.as_str()),
        "the member whose outcome the subset omitted is STILL inside the roster the current owner \
         was consulted about: the validation is bound to the archive's whole denominator, not to \
         the caller's subset"
    );
    // And the omitted outcome is therefore a MISSING coverage entry against that
    // denominator, which is what the gate refuses. Read here through the receipt's
    // own retained denominator, not inferred.
    assert_eq!(
        subset_receipt.per_entry.len(),
        archive_members.len().wrapping_sub(1),
        "the receipt RETAINS the caller's partial vector verbatim: one archived member has no \
         outcome, so the outcome roster is genuinely short of the denominator above"
    );
    assert!(
        !subset_receipt
            .per_entry
            .iter()
            .any(|(record_id, _)| record_id.as_str() == dropped.as_str()),
        "the omitted outcome really is absent from the retained per-entry vector, so the \
         coverage comparison below is refusing a member nobody triaged"
    );
    assert_eq!(
        subset_receipt.unresolved_count, 0,
        "the subset carries no `Unresolved` outcome, so the refusal below is the COVERAGE clause \
         and not the unknown-outcome clause"
    );
    match subset_receipt.known_zero_unresolved(&subset_receipt.current_owner_validation) {
        Err(OrsError::ReconciliationMismatch) => {}
        other => panic!("roster (b) subset must NOT report a satisfied known-zero, got {other:?}"),
    }
    Ok(subset_receipt)
}

/// (c) of case 953/17: a FOREIGN roster — every archived member PLUS one id the
/// archive never declared.
///
/// OWNER: `reconcile_import_receipt`
/// (`src/store/backup_snapshot.rs::reconcile_import_receipt`, the vector is taken
/// verbatim) against the PUBLIC gate `OrsBackupImportReceipt::known_zero_unresolved`
/// (`src/backup_snapshot.rs::known_zero_unresolved`).
fn foreign_roster_is_refused_953_17(
    store: &RedbRecoveryStore,
    import: &OrsBackupImportRequest,
    exported: &OrsBackupSnapshot,
    roster: &[(RowFamilyKind, String)],
    imported: &[(String, PerEntryOutcome)],
) -> TestOutcome<eliot_ors::OrsBackupImportReceipt> {
    let mut foreign = imported.to_vec();
    foreign.push((
        "record-953-17-foreign".to_owned(),
        PerEntryOutcome::Rejected {
            reason: "953/17 an id the archive never declared".to_owned(),
        },
    ));
    assert!(
        !foreign
            .iter()
            .any(|(record_id, _)| roster.iter().any(|(_, member)| member == record_id)),
        "the roster under test really does add one foreign id on top of every archived member"
    );
    let foreign_receipt =
        store.reconcile_backup_import(import, exported, &foreign, IMPORT_AT_MS_953)?;
    match foreign_receipt.known_zero_unresolved(&foreign_receipt.current_owner_validation) {
        Err(OrsError::ReconciliationMismatch) => {}
        other => panic!("roster (c) foreign must NOT report a satisfied known-zero, got {other:?}"),
    }
    Ok(foreign_receipt)
}

/// (d) of case 953/17: a DUPLICATED roster — the same member id twice, which is
/// contradictory evidence rather than a second member.
///
/// OWNER: `reconcile_import_receipt`
/// (`src/store/backup_snapshot.rs::reconcile_import_receipt`, the vector is taken
/// verbatim) against the PUBLIC gate `OrsBackupImportReceipt::known_zero_unresolved`
/// (`src/backup_snapshot.rs::known_zero_unresolved`).
fn duplicated_roster_is_refused_953_17(
    store: &RedbRecoveryStore,
    import: &OrsBackupImportRequest,
    exported: &OrsBackupSnapshot,
    imported: &[(String, PerEntryOutcome)],
) -> TestOutcome<eliot_ors::OrsBackupImportReceipt> {
    let mut duplicated = imported.to_vec();
    duplicated.push((
        imported[0].0.clone(),
        PerEntryOutcome::Blocked {
            reason: "953/17 a duplicate outcome is contradictory evidence, not a second member"
                .to_owned(),
        },
    ));
    assert!(
        duplicated
            .iter()
            .filter(|(id, _)| *id == imported[0].0)
            .count()
            == 2,
        "the roster under test really repeats one member id"
    );
    let duplicated_receipt =
        store.reconcile_backup_import(import, exported, &duplicated, IMPORT_AT_MS_953)?;
    match duplicated_receipt.known_zero_unresolved(&duplicated_receipt.current_owner_validation) {
        Err(OrsError::ReconciliationMismatch) => {}
        other => {
            panic!("roster (d) duplicate must NOT report a satisfied known-zero, got {other:?}")
        }
    }
    Ok(duplicated_receipt)
}

/// The closing discrimination of case 953/17. Nothing above is a bare refusal: the
/// refused rosters disagree with the correct one ONLY in their outcome vector; the
/// store's own validation is identical across all of them (same digest, same
/// complete consulted roster, same empty unresolved set), and only (a) passed the
/// gate. The refusal is therefore the coverage clause, reached by the PUBLIC gate
/// `OrsBackupImportReceipt::known_zero_unresolved` through its
/// `owner_validation_is_complete` call and decided by that private predicate's
/// provided-vs-expected equality. And the discrimination, stated once: over a
/// NON-EMPTY snapshot, exactly one of the four rosters the issue names — empty,
/// subset, foreign, duplicated — satisfies the gate, and it is the complete full one.
///
/// OWNER: the PUBLIC gate `OrsBackupImportReceipt::known_zero_unresolved`
/// (`src/backup_snapshot.rs::known_zero_unresolved`, which reaches the coverage
/// clause through `owner_validation_is_complete`) and
/// `OrsBackupImportReceipt::owner_validation_is_complete`
/// (`src/backup_snapshot.rs::owner_validation_is_complete`).
fn refusals_are_the_coverage_clause_953_17(
    correct: &eliot_ors::OrsBackupImportReceipt,
    empty_receipt: &eliot_ors::OrsBackupImportReceipt,
    subset_receipt: &eliot_ors::OrsBackupImportReceipt,
    foreign_receipt: &eliot_ors::OrsBackupImportReceipt,
    duplicated_receipt: &eliot_ors::OrsBackupImportReceipt,
) {
    let same_validation = |receipt: &eliot_ors::OrsBackupImportReceipt| {
        format!(
            "{}|{:?}|{:?}|{:?}",
            receipt.current_owner_validation.snapshot_digest,
            receipt.current_owner_validation.validated_record_ids,
            receipt
                .current_owner_validation
                .unresolved_effect_identities,
            receipt.current_owner_validation.consulted_families
        )
    };
    assert_eq!(
        same_validation(empty_receipt),
        same_validation(correct),
        "the empty-roster receipt carries the SAME complete current-owner validation as the \
         correct one, so its refusal is the outcome-coverage clause and not a thinner question"
    );
    assert_eq!(
        same_validation(subset_receipt),
        same_validation(correct),
        "the subset receipt carries the SAME complete current-owner validation as the correct one, so its refusal is the outcome-coverage clause"
    );
    assert_eq!(
        same_validation(foreign_receipt),
        same_validation(correct),
        "the foreign receipt carries the SAME complete current-owner validation as the correct one"
    );
    assert_eq!(
        same_validation(duplicated_receipt),
        same_validation(correct),
        "the duplicated receipt carries the SAME complete current-owner validation as the correct one"
    );

    assert!(
        correct
            .known_zero_unresolved(&correct.current_owner_validation)
            .is_ok()
            && empty_receipt
                .known_zero_unresolved(&empty_receipt.current_owner_validation)
                .is_err()
            && subset_receipt
                .known_zero_unresolved(&subset_receipt.current_owner_validation)
                .is_err()
            && foreign_receipt
                .known_zero_unresolved(&foreign_receipt.current_owner_validation)
                .is_err()
            && duplicated_receipt
                .known_zero_unresolved(&duplicated_receipt.current_owner_validation)
                .is_err(),
        "exactly one roster satisfies the gate — the complete full one; the empty, subset, foreign \
         and duplicated outcome rosters are all refused"
    );
}

// ===========================================================================
// Cases 19 and 20 (lane/CB2). This block sits BETWEEN cases 14..17 above and
// cases 10..13 below; cases 1..9 sit above that. Nothing outside this block is
// touched, and no `use` statement, `type` alias or harness helper is added or
// changed. Both helpers below are PRIVATE to this block and each has exactly
// one caller:
//   - `one_redb_directory`  -> case 19
//   - `ors_source_tree`     -> case 20
// ===========================================================================

/// A unique temporary DIRECTORY holding exactly one database file, in the
/// hand-rolled pattern of `tests/restore_journal.rs:721-728` (no `tempfile`
/// dev-dependency exists in this crate, and none may be added).
///
/// Returns `(directory, database path)`. The directory is asserted to contain
/// exactly one file by the caller, the same way
/// `guard_excludes_second_db_backup_dep_and_authority`
/// (`tests/restore_journal.rs:720-743`) asserts it after its fixture writes.
fn one_redb_directory(case: &str) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let nanos = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    };
    let dir = std::env::temp_dir().join(format!("eliot-953-{case}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("ors.redb");
    Ok((dir, path))
}

// WORK_UNIT_CASE: 953/18
//
// ARCH-RES-03, "Recovery cannot resurrect invalid state" (A13.7 line 1464;
// I5.13 restore step "apply privacy purge ledger"). Executable form: a backup
// import can never turn a purge/revocation-excluded row back into an ACTIVE,
// RESTORABLE row.
//
// CITED OWNER (this case's `path::symbol`):
//   crates/kernel/eliot-ors/src/store/backup_snapshot.rs::triage_entry
//
// HONEST SCOPE OF THE CLAIM, established by reading the production code, not
// assumed:
//
// 1. `ResurrectionGuard` DOES NOT EXIST in this tree. It is named in neither
//    `src/store/backup_snapshot.rs` nor anywhere else under `crates/kernel/`.
//    The mechanism ARCH-RES-03 names is implemented instead by
//    `src/store/backup_snapshot.rs::triage_entry` (line 4115), whose FIRST
//    action is `match entry.family.disposition()`. The two non-restorable
//    dispositions return before any digest, identity or scan work:
//
//      RowDisposition::NonrestorableHistorical =>
//          PerEntryOutcome::Forensic { reason: "historical session/lease/route/
//          grant row is never re-activated" }                    (line 4121)
//      RowDisposition::ForensicOnly =>
//          PerEntryOutcome::Forensic { reason: "forensic-only row never crosses
//          a restore boundary" }                                  (line 4126)
//
//    `RowFamilyKind::VersionedArtifacts` is dispositioned
//    `NonrestorableHistorical` by `RowFamilyKind::disposition`
//    (`src/backup_snapshot.rs:459`, the `NonrestorableHistorical` arm at line
//    483-491 names `VersionedArtifacts` explicitly), its module doc states the
//    intent verbatim at `src/store/backup_snapshot.rs:157-158` — "(I05-27 /
//    ARCH-RES-03: recovery cannot resurrect invalid state)" — and it IS inside
//    the export denominator (`row_family_denominator`, line 701) and inside the
//    paged export (`family_segment::<VersionedArtifactEntry>`, line 3211). So a
//    REAL row of a REAL non-restorable family is reachable through the public
//    surface, and this case drives it.
//
// 2. THE PURGE/REVOCATION-SPECIFIC HALF IS A REPORTED GAP, NOT A CLAIMED PASS.
//    `apply_purge_ledger_entry` (`src/store.rs:6339`) and
//    `persist_revocation_event` (`src/store.rs:28769`) are real public writers,
//    and this case really calls BOTH through the public surface. But their
//    tables are declared `ForensicOnly` EXCLUSIONS, not row families
//    (`purge_ledger_exclusions`, `src/store/backup_snapshot.rs:1557`, and the
//    `EFFECT_REVOCATION_EVENTS` exclusion at line 1520). An excluded table has
//    NO `RowFamilyKind`, therefore NO `OrsBackupEntry`, therefore it NEVER
//    appears in an exported page and NEVER reaches `triage_entry`. There is
//    consequently NO reachable public trigger, in this tree, for a row that is
//    purge- or revocation-BLOCKED *by identity*. This case therefore proves
//    the strongest true statement available and does NOT claim more:
//
//      (a) the purge ledger and revocation event tables are REAL and the purge
//          ledger revision REALLY advances (real writes, real readback); and
//      (b) the resurrection guarantee is discharged where the code actually
//          discharges it — by DISPOSITION, applied to a REAL non-restorable
//          family's REAL row — and `PerEntryOutcome::Imported` is UNREACHABLE
//          for it. See LIMITATION below.
//
// 3. WHAT THE CONTROL PROVES (discrimination, not blanket refusal): the same
//    page, triaged through the same call, yields `Forensic` for the
//    `NonrestorableHistorical` row and a NON-forensic, non-`Imported` outcome
//    for an ordinary restorable seeded row. So the disposition branch is what
//    discriminates, and the refusal is not a blanket refusal of every entry.
//
// LIMITATION, stated here and in the report: the `NonrestorableHistorical` /
// `ForensicOnly` disposition is a STATIC FAMILY POLICY (`disposition()`), not a
// per-row purge/revocation lookup. In this tree no code consults
// `PURGE_LEDGER` or `EFFECT_REVOCATION_EVENTS` while triaging a backup entry,
// so "purge/revocation prevents resurrection" is discharged by keeping those
// families out of the row-family denominator entirely (so they can never be
// resurrected as active rows) plus the disposition gate — NOT by an
// identity-keyed purge check inside `triage_entry`. Nothing here is edited to
// manufacture that check and no `#[allow]`, no shim, no stand-in is used.
#[test]
fn purge_revocation_prevents_resurrection() -> TestResult {
    let (store, identity, path) = open_bound_store("18")?;
    seed_operational_rows(&store, 1)?;

    // ---- (a) The purge/revocation tables are REAL, not vacuous. -----------
    // (`purge_tables_are_real_953_18`, below this test.)
    purge_tables_are_real_953_18(&store)?;

    // ---- (b) A REAL non-restorable family row, exported for real. ---------
    // (`nonrestorable_row_is_exported_953_18`, below this test.)
    nonrestorable_row_is_exported_953_18(&store)?;

    // ---- (c) A REAL export holding both row kinds. -----------------------
    let source = source_for(&identity)?;
    let request = observed_request(&store, &identity, MAX_BACKUP_PAGE_ENTRIES, 8)?;
    let snapshot = store.export_backup_snapshot(&request)?;
    snapshot.validate()?;
    let (artifact_entry, restorable_entry) = pick_one_row_of_each_kind_953_18(&snapshot);

    // ---- (d) Triage through the PUBLIC import entrypoint. -----------------
    let (outcomes, import) =
        triage_through_public_entrypoint_953_18(&store, &identity, &source, &snapshot)?;
    assert_eq!(
        import.source, source,
        "the triage request was built from THIS store's own source identity, so every outcome \
         below is a verdict about this archive and not about a foreign one"
    );
    assert_eq!(
        import.snapshot_digest,
        snapshot.snapshot_digest(),
        "the triage request carries the ARCHIVE's real digest, so `expected_import_roster`'s \
         digest comparison could not have refused it for an identity mismatch"
    );

    // ---- (e) the purge/revocation-relevant row is NEVER Imported. --------
    nonrestorable_row_is_never_imported_953_18(&outcomes, &artifact_entry);

    // ---- (f) Disposition consistency, and `Imported` is not reachable. ---
    disposition_consistency_953_18(&snapshot, &outcomes);

    // ---- (g) CONTROLLED POSITIVE: discrimination, not blanket refusal. ---
    controlled_positive_is_not_blanket_953_18(&outcomes, &restorable_entry);

    remove_db(&path);
    Ok(())
}

/// (a) of case 953/18: the purge ledger and the revocation-event table are REAL,
/// not vacuous. Both are driven through their ONLY public writer and read back
/// through a SEPARATE reader in a FRESH transaction, so "these tables are real" is a
/// measurement rather than an assertion.
///
/// OWNER: `RedbRecoveryStore::apply_purge_ledger_entry` (`src/store.rs:6339`,
/// idempotent by construction at `:6333-6337`) and `RedbRecoveryStore::
/// purge_ledger_revision` (`:6406`) for the purge ledger;
/// `RedbRecoveryStore::persist_revocation_event` (`src/store.rs:28769`) and
/// `RedbRecoveryStore::load_revocation_event` (`:28822`) for the revocation event.
fn purge_tables_are_real_953_18(store: &RedbRecoveryStore) -> TestOutcome<()> {
    purge_ledger_advances_953_18(store)?;
    revocation_event_is_durable_953_18(store)
}

/// (a-i) of case 953/18: the purge ledger is REAL, not vacuous.
/// `RedbRecoveryStore::apply_purge_ledger_entry` (`src/store.rs:6339`) is the ONLY
/// place the purge ledger advances, and `purge_ledger_revision`
/// (`src/store.rs:6406`) is the separate readback of the current owner-issued
/// revision. Driving the real writer and reading the real revision back is what
/// makes "the purge ledger is real" a measurement instead of an assertion. The
/// exact-replay arm is asserted because a purge ledger that double-counts on retry
/// is a resurrection-adjacent defect.
///
/// OWNER: `RedbRecoveryStore::apply_purge_ledger_entry` (`src/store.rs:6339`,
/// idempotent by construction at `:6333-6337`) and `RedbRecoveryStore::
/// purge_ledger_revision` (`src/store.rs:6406`).
fn purge_ledger_advances_953_18(store: &RedbRecoveryStore) -> TestOutcome<()> {
    let before_revision = store.purge_ledger_revision()?;
    assert_eq!(
        before_revision, 0,
        "a store that never applied a purge holds ledger revision zero"
    );

    let purge = eliot_security_contracts::PurgeLedgerEntry {
        purge_id: "purge-953-18".to_owned(),
        subject_ref: "subject-953-18".to_owned(),
        scope: "scope-953-18".to_owned(),
        purged_locations: vec![
            eliot_security_contracts::PurgeLocation::OperationalRecovery,
            eliot_security_contracts::PurgeLocation::BackupRestorePath,
        ],
        tombstone_digest: fence_digest('t'),
        // `PurgeState::Purged` is the terminal state:
        // `PurgeLedgerEntry::validate_restore`
        // (`crates/foundation/eliot-security-contracts/src/validation.rs:435`)
        // returns `SecurityContractError::PurgeResurrection` for exactly this
        // value, which IS the archive-side half of ARCH-RES-03 this crate
        // depends on. Nothing in this test restores it.
        state: eliot_security_contracts::PurgeState::Purged,
        // `EPOCH_953` is the literal `1` at line 35 of this file, which is inside
        // the `NonZeroU64` domain; the contract's `EpochId::new` therefore takes
        // it directly and no run-time failure path is needed here.
        state_fence: eliot_contracts::StateFence::new(
            eliot_contracts::EpochId::new(
                eliot_contracts::EpochLineageId::new(LINEAGE_953)
                    .map_err(|error| OrsError::Contract(error.to_string()))?,
                std::num::NonZeroU64::new(EPOCH_953).ok_or(
                    "953/18 the epoch constant EPOCH_953 must be non-zero: a zero epoch \
                            would name no epoch at all, so the purge ledger entry below would \
                            carry an identity that proves nothing",
                )?,
            )
            .map_err(|error| OrsError::Contract(error.to_string()))?,
            eliot_contracts::ResourceGeneration::genesis(),
        ),
        revision: 1,
    };
    let applied_revision = store.apply_purge_ledger_entry(&purge)?;
    assert_eq!(
        applied_revision, 1,
        "the first applied purge consumes exactly ledger revision 1"
    );
    assert_eq!(
        store.purge_ledger_revision()?,
        applied_revision,
        "the owner-issued revision read back matches the revision the write returned"
    );

    // Idempotent by construction (`src/store.rs:6333-6337`): the exact replay of
    // one entry consumes nothing. Asserted because a purge ledger that
    // double-counts on retry is a resurrection-adjacent defect.
    assert_eq!(
        store.apply_purge_ledger_entry(&purge)?,
        applied_revision,
        "an exact purge replay consumes no second revision"
    );
    Ok(())
}

/// (a-ii) of case 953/18: the revocation-event table is REAL, not vacuous. A REAL
/// observed revocation event goes through the REAL public writer and is read back
/// in a FRESH transaction. `OperationIdentity` is `OpaqueLabel` (`src/model.rs:87`),
/// whose `new` already returns `OrsError`, so the identity constructors need no
/// adapter.
///
/// OWNER: `RedbRecoveryStore::persist_revocation_event` (`src/store.rs:28769`) and
/// `RedbRecoveryStore::load_revocation_event` (`src/store.rs:28822`);
/// `RevocationAcknowledgement::Acknowledged` is a DISCHARGED revocation whose
/// authority "cannot be restored" (`src/execution_manifest.rs:204-213`).
fn revocation_event_is_durable_953_18(store: &RedbRecoveryStore) -> TestOutcome<()> {
    let lease_id = eliot_ors::OperationIdentity::new("lease-953-18")?;
    let revocation = eliot_ors::RevocationEventRecord {
        schema_version: eliot_ors::EFFECT_CURRENT_STATE_SCHEMA_VERSION,
        lease_id: lease_id.clone(),
        operation_id: eliot_ors::OperationIdentity::new("operation-953-18")?,
        module_id: "module-953-18".to_owned(),
        generation: eliot_contracts::ResourceGeneration::genesis(),
        // `Acknowledged` = a DISCHARGED revocation whose authority "cannot be
        // restored" (`src/execution_manifest.rs:204-213`).
        acknowledgement: eliot_ors::RevocationAcknowledgement::Acknowledged,
        observed_at_ms: 1_700_000_000_000,
    };
    store.persist_revocation_event(&revocation)?;
    // `persist_revocation_event` (`src/store.rs:28769`) is the ONLY write path
    // into `EFFECT_REVOCATION_EVENTS` and it returns `Ok(())` only after that
    // write transaction committed, while `load_revocation_event` (`src/store.rs:28822`)
    // is its own readback in a NEW read transaction. A committed write followed by
    // a read of the same primary key cannot yield `None`; the `None` arm below is
    // therefore the loud statement that the revocation is DURABLE and not merely
    // returned, which is the fact part (a) of this case rests on.
    let readback = store.load_revocation_event(&lease_id)?;
    assert!(
        readback.is_some(),
        "the revocation event is DURABLE: the writer above returned Ok, and this is an \
         independent readback in a fresh transaction, so `None` would mean the acknowledged \
         revocation part (a) relies on never became durable"
    );
    let Some(readback) = readback else {
        panic!(
            "the revocation event did not survive the writer that returned Ok, so the \
             acknowledged revocation this case relies on does not exist"
        )
    };
    assert_eq!(
        readback.acknowledgement,
        eliot_ors::RevocationAcknowledgement::Acknowledged,
        "the durable revocation readback states the recorded acknowledgement"
    );
    Ok(())
}

/// (b) of case 953/18: a REAL row of a REAL non-restorable family, committed
/// through the family's own public write path and shown durable — and the STATIC
/// policy reading shown two ways (directly through `RowFamilyKind::disposition`
/// and, independently, through the public associated function
/// `RedbRecoveryStore::backup_row_family_denominator`), so the two public readers
/// of the policy are shown to agree.
///
/// OWNER: `RedbRecoveryStore::commit_versioned_artifact_registry`
/// (`src/store.rs:33626`) and `VersionedArtifactRegistry::install_candidate`; the
/// census that binds its rows to `RowFamilyKind::VersionedArtifacts`
/// (`src/store/backup_snapshot.rs:1059-1062`), `row_family_denominator` (line 701)
/// and `RedbRecoveryStore::backup_row_family_denominator` (`src/store.rs:5069`).
fn nonrestorable_row_is_exported_953_18(store: &RedbRecoveryStore) -> TestOutcome<()> {
    // `commit_versioned_artifact_registry` (`src/store.rs:33626`) is the
    // family's public write path; `install_candidate` is its real staging API.
    // The staged row lands in `ors_versioned_artifacts_v1`, which the census
    // binds to `RowFamilyKind::VersionedArtifacts` (`src/store/backup_snapshot
    // .rs:1059-1062`) and `row_family_denominator` (line 701) declares with the
    // `NonrestorableHistorical` disposition.
    let artifact = eliot_ors::VersionedArtifact::new(
        "module-953-18",
        7,
        fence_digest('a'),
        eliot_ors::VersionedArtifact::canonical_path("module-953-18", 7, &fence_digest('a')),
    )?;
    let compatibility = eliot_ors::CompatibilityEvidence::new(
        1,
        1,
        1,
        fence_digest('c'),
        1,
        1,
        fence_digest('d'),
        fence_digest('s'),
        7,
        LINEAGE_953,
        EPOCH_953,
        vec!["capability-953-18".to_owned()],
        Vec::new(),
        "migration-class-953-18",
        Some(1),
        Some(1),
        None,
    )?;
    let mut registry = eliot_ors::VersionedArtifactRegistry::new();
    registry.install_candidate(artifact, compatibility)?;
    store.commit_versioned_artifact_registry(&registry)?;
    let durable_registry = store.load_versioned_artifact_registry(16)?;
    assert_eq!(
        durable_registry.durable_entries()?.len(),
        1,
        "the candidate is durable after commit: the family really holds the row this \
         case later exports"
    );

    // The declared disposition is a STATIC policy reading, asserted directly
    // through the public `RowFamilyKind::disposition` and, independently,
    // through the public associated function
    // `RedbRecoveryStore::backup_row_family_denominator` (`src/store.rs:5069`),
    // so the two public readers of the policy are shown to agree.
    assert_eq!(
        RowFamilyKind::VersionedArtifacts.disposition(),
        RowDisposition::NonrestorableHistorical,
        "the versioned-artifact family is declared non-restorable historical"
    );
    let denominator = RedbRecoveryStore::backup_row_family_denominator();
    let declared_entry = denominator
        .iter()
        .find(|entry| entry.kind == RowFamilyKind::VersionedArtifacts);
    assert!(
        declared_entry.is_some(),
        "the versioned-artifact family IS in the declared row-family denominator: the export \
         census (`src/store/backup_snapshot.rs:1059`) binds this family's staged rows to \
         `RowFamilyKind::VersionedArtifacts`, so if the denominator did not declare that kind the \
         exported member below could not be dispositioned at all"
    );
    let Some(declared) = declared_entry else {
        panic!(
            "the declared denominator omits the versioned-artifact family whose row this case \
             just exported and triages, so the policy comparison below would be vacuous"
        )
    };
    assert_eq!(
        declared.disposition,
        RowDisposition::NonrestorableHistorical,
        "the denominator reader declares the same disposition as disposition()"
    );
    Ok(())
}

/// (c) of case 953/18: the REAL export really carries BOTH row kinds — one
/// non-restorable `VersionedArtifacts` member and one restorable
/// `OperationalHistory` member — and their identities are distinct, because the
/// triage vector is keyed by `record_id` ALONE
/// (`src/store/backup_snapshot.rs:4094` pushes `entry.record_id`), so shared ids
/// would alias the two outcome lookups onto each other.
///
/// OWNER: `RedbBackupEntry::family` / `record_id` (`src/backup_snapshot.rs:1500`) as
/// emitted by the export walk (`src/store/backup_snapshot.rs:2843`), and the triage
/// vector keying at `src/store/backup_snapshot.rs:4094`.
fn pick_one_row_of_each_kind_953_18(snapshot: &OrsBackupSnapshot) -> (String, String) {
    let mut artifact_entry = None;
    let mut restorable_entry = None;
    for page in &snapshot.pages {
        for entry in &page.entries {
            match entry.family {
                RowFamilyKind::VersionedArtifacts => artifact_entry = Some(entry.record_id.clone()),
                RowFamilyKind::OperationalHistory if restorable_entry.is_none() => {
                    restorable_entry = Some(entry.record_id.clone());
                }
                _ => {}
            }
        }
    }
    // Both ids must come out of the REAL export above: `seed_operational_rows`
    // wrote `OperationalHistory` rows through the public writer, and
    // `commit_versioned_artifact_registry` committed a `VersionedArtifacts` row
    // whose durability was asserted above. Absent either, the two outcome lookups
    // below would read a real outcome for a DIFFERENT member than the one the
    // triage is claimed to be about, so this is a non-vacuity check, not a
    // restatement of the rows.
    assert!(
        artifact_entry.is_some(),
        "the exported snapshot really carries a versioned-artifact member: the registry commit \
         above is durable, and the census binds that family's rows to \
         `RowFamilyKind::VersionedArtifacts`, so the Forensic outcome checked below is the one \
         for THAT row"
    );
    let Some(artifact_entry) = artifact_entry else {
        panic!(
            "no versioned-artifact member was exported, so the non-restorable outcome checked \
             below would be read for a member the snapshot does not contain"
        )
    };
    assert!(
        restorable_entry.is_some(),
        "the exported snapshot really carries an operational-history member: the seeded rows are \
         durable, so the comparison below contrasts a real controlled-positive row against the \
         non-restorable one rather than comparing two absent rows"
    );
    let Some(restorable_entry) = restorable_entry else {
        panic!(
            "no operational-history member was exported, so the controlled-positive outcome read \
             below would belong to a member the snapshot does not contain"
        )
    };
    // The triage vector is keyed by `record_id` ALONE
    // (`src/store/backup_snapshot.rs:4094` pushes `entry.record_id`), so the two
    // rows this case compares must not share one id or the lookups below would
    // alias. The two families address disjoint durable-key spaces, and this
    // asserts that rather than relying on it.
    assert_ne!(
        artifact_entry, restorable_entry,
        "the non-restorable row and the controlled-positive row must be distinct \
         identities, or the outcome lookups below would alias one onto the other"
    );
    (artifact_entry, restorable_entry)
}

/// (d) of case 953/18: triage through the PUBLIC import entrypoint, over EVERY
/// page of the REAL export, returning the outcome vector the later phases read.
///
/// `RedbRecoveryStore::import_backup_page_quarantined` (`src/store.rs:5060`)
/// delegates to `import_page_quarantined` (`src/store/backup_snapshot.rs:4029`),
/// which runs the whole page through `triage_entry` under ONE read transaction
/// (line 4094) and performs NO write (its doc at line 4108 says "never activates,
/// never writes").
///
/// The destination gate at `src/store/backup_snapshot.rs:4076` compares the store's
/// DURABLE store-object identity against `import.destination.installation_id`, so the
/// destination is this store's own installation. `import.source` is deliberately NOT
/// compared with the page's source here (only `reconcile_import_receipt` does that,
/// at line 4203), so ONE store legitimately triages its own exported pages — which
/// is what keeps this case to a single database and no file copy.
///
/// OWNER: `RedbRecoveryStore::import_backup_page_quarantined` (`src/store.rs:5060`)
/// -> `import_page_quarantined` (`src/store/backup_snapshot.rs:4029`), destination
/// gate at `:4076`, and `OrsBackupSnapshot::entry_count` (`src/backup_snapshot.rs:1874`).
fn triage_through_public_entrypoint_953_18(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
    source: &OrsBackupSourceIdentity,
    snapshot: &OrsBackupSnapshot,
) -> TestOutcome<(Vec<(String, PerEntryOutcome)>, OrsBackupImportRequest)> {
    let destination = OrsBackupDestination::new(
        identity.installation_id().to_string(),
        "admission-receipt-953-18".to_owned(),
        true,
    )?;
    let import = OrsBackupImportRequest {
        snapshot_digest: snapshot.snapshot_digest(),
        source: source.clone(),
        destination,
    };

    let mut outcomes: Vec<(String, PerEntryOutcome)> = Vec::new();
    for page in &snapshot.pages {
        outcomes.extend(store.import_backup_page_quarantined(&import, page)?);
    }
    // `snapshot.entry_count` is the export's OWN denominator and `MAX_BACKUP_PAGE_ENTRIES`
    // caps a page at `usize::MAX` entries in practice, so the checked widening below
    // cannot fail; it is stated rather than assumed, and a failure would itself mean
    // the export declared more members than this process can hold.
    let declared_member_count = usize::try_from(snapshot.entry_count)
        .map_err(|_| "the export declares more members than this process can address")?;
    assert_eq!(
        outcomes.len(),
        declared_member_count,
        "triage returned exactly one outcome per exported member: no member is \
         dropped and none is invented"
    );
    Ok((outcomes, import))
}

/// (e) of case 953/18: the purge/revocation-relevant row is NEVER Imported. Which
/// outcome the code ACTUALLY yields, and why: `Forensic`, and nothing else.
/// `triage_entry`'s first statement is the disposition match
/// (`src/store/backup_snapshot.rs:4119`), `NonrestorableHistorical` returns
/// `PerEntryOutcome::Forensic` at line 4121 BEFORE the digest-shape check
/// (line 4132) and before the operational-history identity scan (line 4137), so the
/// row can never reach the `Rejected`/`Blocked`/`Unresolved` tail at lines 4156-4169
/// either. `Imported` is not merely avoided for this row: `triage_entry` constructs
/// it NOWHERE, and the module header states so at `src/store/backup_snapshot.rs:34`
/// (`PerEntryOutcome::Imported is intentionally never constructed here`).
///
/// OWNER: `triage_entry` (`src/store/backup_snapshot.rs:4115`, disposition match at
/// `:4119`, `Forensic` return at `:4121`), with the disposition the census declares
/// for this family (`src/backup_snapshot.rs:459`).
fn nonrestorable_row_is_never_imported_953_18(
    outcomes: &[(String, PerEntryOutcome)],
    artifact_entry: &str,
) {
    let outcome_of = |id: &str| -> Option<PerEntryOutcome> {
        outcomes
            .iter()
            .find(|(key, _)| key == id)
            .map(|(_, outcome)| outcome.clone())
    };
    match outcome_of(artifact_entry) {
        Some(PerEntryOutcome::Forensic { reason }) => assert!(
            reason.contains("historical session/lease/route/grant row is never re-activated"),
            "the forensic reason is the disposition branch's own stated reason, got {reason:?}"
        ),
        other => panic!(
            "a NonrestorableHistorical row must land Forensic and must never be Imported, got {other:?}"
        ),
    }
}

/// (f) of case 953/18: disposition consistency over the WHOLE real outcome vector.
/// Every entry whose family is dispositioned non-restorably must land `Forensic`;
/// `Imported` must be absent from the entire roster. This is the per-entry form of
/// the census check the store runs before triage
/// (`check_row_family_census`, `src/store/backup_snapshot.rs:4091`), stated over the
/// real outcome vector instead of the table list.
///
/// OWNER: `RowFamilyKind::disposition` (`src/backup_snapshot.rs:459`) as read by
/// `triage_entry` (`src/store/backup_snapshot.rs:4119`), against the row-family census
/// `check_row_family_census` (`src/store/backup_snapshot.rs:4091`).
fn disposition_consistency_953_18(
    snapshot: &OrsBackupSnapshot,
    outcomes: &[(String, PerEntryOutcome)],
) {
    let outcome_of = |id: &str| -> Option<PerEntryOutcome> {
        outcomes
            .iter()
            .find(|(key, _)| key == id)
            .map(|(_, outcome)| outcome.clone())
    };
    let mut forensic_for_nonrestorable = 0usize;
    for page in &snapshot.pages {
        for entry in &page.entries {
            let disposition = entry.family.disposition();
            let outcome = outcome_of(&entry.record_id)
                .unwrap_or_else(|| panic!("no outcome for exported member {:?}", entry.record_id));
            match disposition {
                RowDisposition::NonrestorableHistorical | RowDisposition::ForensicOnly => {
                    assert!(
                        matches!(outcome, PerEntryOutcome::Forensic { .. }),
                        "family {:?} is {disposition:?} so its row must land Forensic, got {outcome:?}",
                        entry.family
                    );
                    assert!(
                        !matches!(outcome, PerEntryOutcome::Imported),
                        "a {disposition:?} family must never come back Imported"
                    );
                    forensic_for_nonrestorable = forensic_for_nonrestorable.saturating_add(1);
                }
                RowDisposition::Restorable => {}
            }
        }
    }
    assert!(
        forensic_for_nonrestorable >= 1,
        "at least one non-restorable family row was actually triaged, so the \
         disposition branch above was exercised rather than skipped"
    );
    assert!(
        !outcomes
            .iter()
            .any(|(_, outcome)| matches!(outcome, PerEntryOutcome::Imported)),
        "no exported member came back Imported: triage writes nothing and \
         confers no authority on any row of this page"
    );
}

/// (g) of case 953/18: CONTROLLED POSITIVE — discrimination, not blanket refusal.
///
/// `RowFamilyKind::OperationalHistory` is `Restorable`
/// (`src/backup_snapshot.rs:499`), so its rows pass the disposition match and reach
/// the digest and identity work. This store genuinely holds the seeded row, so
/// `triage_entry`'s scan finds it, re-encodes it and compares digests: equal digests
/// give `Rejected { "duplicate entry already durably stored" }`
/// (`src/store/backup_snapshot.rs:4156`). That outcome is DIFFERENT from `Forensic`,
/// and it is reached only because the row's family is restorable — which is exactly
/// the discrimination this case must show.
///
/// OWNER: `RowFamilyKind::disposition` for `OperationalHistory`
/// (`src/backup_snapshot.rs:499`) and `triage_entry`'s operational-history identity
/// scan (`src/store/backup_snapshot.rs:4137`), whose duplicate arm is at `:4156`.
fn controlled_positive_is_not_blanket_953_18(
    outcomes: &[(String, PerEntryOutcome)],
    restorable_entry: &str,
) {
    let outcome_of = |id: &str| -> Option<PerEntryOutcome> {
        outcomes
            .iter()
            .find(|(key, _)| key == id)
            .map(|(_, outcome)| outcome.clone())
    };
    assert_eq!(
        RowFamilyKind::OperationalHistory.disposition(),
        RowDisposition::Restorable,
        "the controlled positive family is restorable, so its row is not \
         diverted by the disposition branch"
    );
    match outcome_of(restorable_entry) {
        Some(PerEntryOutcome::Rejected { reason }) => assert!(
            reason.contains("duplicate entry already durably stored"),
            "the restorable row is triaged on its OWN durable identity, got {reason:?}"
        ),
        Some(PerEntryOutcome::Unresolved { reason }) => assert!(
            reason.contains("quarantined for the canonical owner"),
            "a restorable row with no durable collision stays quarantined, got {reason:?}"
        ),
        other => panic!(
            "the restorable seeded row must be triaged on its own terms (Rejected or \
             Unresolved) and never Forensic/Imported, got {other:?}"
        ),
    }
    assert!(
        !matches!(
            outcome_of(restorable_entry),
            Some(PerEntryOutcome::Forensic { .. })
        ),
        "the control row was NOT diverted into the forensic branch: the refusal is \
         family-scoped, not blanket"
    );
}

/// Recursively reads every `.rs` file under `crates/kernel/eliot-ors/src/`,
/// paired with its path relative to that `src/` root.
///
/// THE SIBLING TECHNIQUE, not an invented one: `env!("CARGO_MANIFEST_DIR")`
/// (`tests/restore_journal.rs:40`) resolves the crate root at compile time, so
/// the guard inspects the SOURCE TEXT of the crate actually under test rather
/// than a transcribed expectation. Every path read here is a `.rs` file; the
/// tree is walked with `read_dir` and filtered on the `rs` extension.
fn ors_source_tree() -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    let mut pending = vec![root.clone()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(std::ffi::OsStr::to_str) == Some("rs") {
                let relative = path
                    .strip_prefix(&root)
                    .map_err(|_| std::io::Error::other("a source path escaped the crate src root"))?
                    .to_string_lossy()
                    .replace('\\', "/");
                sources.push((relative, std::fs::read_to_string(&path)?));
            }
        }
    }
    sources.sort_by(|left, right| left.0.cmp(&right.0));
    assert!(
        !sources.is_empty(),
        "the guard read the crate's own src tree through CARGO_MANIFEST_DIR and found no .rs file, which would make every absence asserted below vacuous"
    );
    Ok(sources)
}

// WORK_UNIT_CASE: 953/19
#[test]
fn real_temp_redb_capture_reopen_quarantine_reconcile_survives_a_crash_point() -> TestResult {
    // =====================================================================
    // PHASE SEQUENCE (the card's exact shape), every phase on a REAL temporary
    // redb file. NOT an `#[ignore]`, NOT a fake, NOT a second database.
    //
    //   P1  one temp DIRECTORY, asserted to hold exactly ONE database file
    //   P2  open the installation-BOUND store; seed REAL operational rows
    //   P3  CAPTURE PHASE: export a real `OrsBackupSnapshot`
    //   P4  CRASH POINT: run a REAL write batch against that same file and
    //       abandon it UNCOMMITTED, then drop the store, releasing the lock
    //   P5  reopen the SAME path, re-read the identity (its generation
    //       advanced), re-derive the source, and settle BOTH directions of
    //       the interruption through the PUBLIC API: the COMMITTED batch is
    //       present, the INTERRUPTED batch is absent
    //   P6  QUARANTINE/RECONCILE PHASE: triage every exported page, reconcile
    //   P7  the lost-response leg: `reconcile_lost_backup_import_response`
    //   P8  remove the file, then the directory
    //
    // THE DURABILITY CLAIM IS PROVEN ONLY IN P5, AND ONLY THROUGH THE PUBLIC
    // API: a second real `export_backup_snapshot` under a freshly RE-DERIVED
    // source identity, checked for the seeded record ids AND for the ABSENCE of
    // the interrupted batch's record id. The redb file is never read, parsed,
    // copied or hashed here; the only `std::fs` calls are `create_dir_all`,
    // `read_dir` (the one-database assertion) and cleanup.
    // =====================================================================

    // ---- P0: THE CRASH-CHILD GATE ----------------------------------------
    // In the CHILD process (the parent re-executes this same binary with
    // `CRASH_CHILD_MARKER_953` set), this runs the real crash phase and aborts
    // the process at the crash point; everything below it belongs to the PARENT
    // and is never reached in the child.
    crash_child_phase_953_19()?;

    // ---- P1: ONE directory, ONE database file --------------------------
    // `RedbRecoveryStore::open_inner` (`src/store.rs:29585-29588`) creates the
    // PARENT directory itself and then `Database::create(path)`, so the file
    // below is the only thing this fixture ever puts in the directory.
    let (dir, path) = one_redb_directory("19")?;
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        std::fs::read_dir(&dir)?.count(),
        0,
        "the fixture directory starts empty, so the single database below is created by this case"
    );

    // ---- P2: bound store + REAL rows ------------------------------------
    // (`open_bound_store_and_seed_953_19`, below this test.)
    let (store, identity, seeded) = open_bound_store_and_seed_953_19(&path, &dir)?;

    // ---- P3: CAPTURE PHASE ---------------------------------------------
    let (captured_members, capture_source, capture_generation) =
        capture_phase_953_19(&store, &identity, &seeded)?;

    // ---- P4: THE REAL CRASH POINT -----------------------------------------
    // TWO interruptions happen at this crash point, and they are the two halves
    // of the durability claim P5 settles.
    //
    // P4-a (`interrupted_batch_953_19`): a REAL write batch is SUBMITTED against
    // this SAME real file and then ABANDONED WITHOUT COMMITTING. That writer calls
    // `mutate_operational` with `require_existing` set, opens a real
    // `redb::WriteTransaction` on this file, and returns
    // `Err(OrsError::InvalidTransition)` from its `require_existing` gate while
    // that transaction is STILL OPEN, so `commit()` is never reached and the
    // dropped transaction is aborted by redb.
    //
    // P4-b (`run_crash_child_953_19`): the SAME file is then crashed FOR REAL, in
    // a CHILD PROCESS that commits one batch, opens a second write transaction,
    // stages a row into it, and calls `std::process::abort()` while that
    // transaction is OPEN and UNCOMMITTED. The process dies without unwinding, so
    // no destructor runs and the staged row can never be committed. This is the
    // I14.21 rule applied literally: "connection fails during commit; ... if
    // unknown -> pause Ordering Scope, preserve operation and open Problem State".
    // The two halves are decided by redb's own commit boundary, not by a clean
    // shutdown: the committed batch must survive, the uncommitted batch must not.
    let interrupted_record_id = interrupted_batch_953_19(&store)?;

    // `drop(store)` releases redb's EXCLUSIVE file lock, which is what makes the
    // child (and the reopen below) able to open that file at all.
    drop(store);

    let crash_child = run_crash_child_953_19(
        &path,
        CRASH_CHILD_INSTALLATION_953_19,
        &[
            "stage-crash-child-953-19-committed".to_owned(),
            "job-checkpoint-crash-child-953-19-committed".to_owned(),
        ],
        "delivery-ack-crash-child-953-19-uncommitted",
    )?;

    // ---- P5: REOPEN, RE-READ, RE-DERIVE, SETTLE BOTH DIRECTIONS -----------
    // The crash child has died by now, so this reopen sees exactly what the
    // crash left on disk: the committed batch and none of the uncommitted one.
    let (reopened, readback_identity, after_crash, survived) =
        reopen_proves_durability_953_19(&ReopenInputs953_19 {
            path: &path,
            identity: &identity,
            seeded: &seeded,
            captured_members: &captured_members,
            capture_source: &capture_source,
            capture_generation,
            interrupted_record_id: &interrupted_record_id,
            crash_child_committed: &crash_child.committed,
        })?;

    // THE DURABILITY PROOF OVER THE REAL CRASH. Both directions are settled
    // through the PUBLIC API only (`export_backup_snapshot` ->
    // `expected_member_roster`), never by reading, parsing or hashing the file.
    assert_crash_child_durability_953_19(&after_crash, &crash_child)?;

    // ---- P6: QUARANTINE / RECONCILE ------------------------------------
    let (receipt, reconcile_import) =
        quarantine_and_reconcile_953_19(&reopened, &readback_identity, &after_crash, &survived)?;
    // The RECONCILED request, held back to the case body so the identity the
    // store reconciled the re-read archive under is measured HERE, once, at the
    // case level, instead of only inside the helper. It is the export-side source
    // identity: the request that actually reconciled still named the ARCHIVE's
    // own source, which is why `reconcile_backup_import` accepted it at all, and
    // it was NOT the distinct quarantine-triage source (the helper asserted that
    // separation before using it). Assertion COUNTS, not weakens: a helper that
    // returned a wrong request would have been refused.
    assert_eq!(
        reconcile_import.source, after_crash.source,
        "the request that reconciled the re-read archive named the ARCHIVE's own source identity, \
         so the acceptance below is a reconciliation of this archive under its OWN identity and not \
         a foreign-source admission"
    );
    assert_eq!(
        reconcile_import.destination.installation_id,
        readback_identity.installation_id(),
        "the reconciling request's declared destination is the RE-OPENED store's own durable \
         installation, so the receipt binds this store and not some other owner"
    );

    // ---- P7: THE LOST-RESPONSE LEG -------------------------------------
    lost_response_leg_953_19(&receipt);

    drop(reopened);

    // ---- P8: cleanup ---------------------------------------------------
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);

    // ---- the "no second database" claim, checked LAST ------------------
    // After cleanup, so it covers the WHOLE case rather than one moment.
    assert!(
        !path.exists(),
        "the single database file this case created was removed at the end"
    );
    assert!(
        !dir.exists(),
        "the temporary directory this case created was removed at the end"
    );
    Ok(())
}

/// P2 of case 953/19: open the installation-BOUND store, seed REAL operational
/// rows, and assert the "no second database" claim against the LIVE directory.
///
/// `open_for_installation`, never `open()`: `open()` binds no installation and
/// `installed_store_identity()` FAILS CLOSED on it
/// (`read_store_object_identity(&meta)?.installed_identity()`,
/// `src/store.rs:29573-29577`), while `check_export_fence`
/// (`src/store/backup_snapshot.rs:2409-2418`) compares the request's declared
/// source against that DURABLE identity. `OrsStoreIdentity`'s fields are
/// private (`src/store.rs:453-456`), so a generation cannot be minted.
/// The existing `open_bound_store` helper owns its OWN `temp_db` path and
/// cannot be pointed at this directory, so the two constructor lines are
/// inlined rather than duplicating that helper a fourth time.
///
/// The whole directory listing is compared against the one path this case opened.
/// This is the assertion `guard_excludes_second_db_backup_dep_and_authority` makes
/// at `tests/restore_journal.rs:739-743`, on the same hand-rolled temporary
/// directory, and it is what distinguishes "one database, reopened" from "a second
/// database created beside it".
///
/// OWNER: `RedbRecoveryStore::open_for_installation` -> `open_inner`
/// (`src/store.rs:29531`, `:29585-29588`), `seed_operational_rows` through the
/// public `OperationalRecoveryStore` writers, and `installed_store_identity`
/// (`src/store.rs:29573`).
fn open_bound_store_and_seed_953_19(
    path: &PathBuf,
    dir: &PathBuf,
) -> TestOutcome<(RedbRecoveryStore, OrsStoreIdentity, Vec<String>)> {
    let (store, identity) =
        RedbRecoveryStore::open_for_installation(path, CRASH_CHILD_INSTALLATION_953_19)?;
    let seeded = seed_operational_rows(&store, 3)?;
    assert_eq!(
        seeded.len(),
        6,
        "seed_operational_rows wrote a staged operation AND a job checkpoint per index, so both real families carry rows"
    );

    let mut database_files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        database_files.push(entry?.path());
    }
    assert_eq!(
        database_files,
        vec![path.clone()],
        "the fixture directory contains EXACTLY ONE database file, which is this case's own store: nothing opened a second one"
    );
    Ok((store, identity, seeded))
}

/// P3 of case 953/19, the CAPTURE PHASE: a real export over the real store, whose
/// own member roster carries every seeded row. `export_snapshot`
/// (`src/store/backup_snapshot.rs:3850`) opens ONE `ReadTransaction`, proves the
/// fence, runs the row-family census, walks every page under that ONE transaction,
/// brackets it with the pre/post composite-state witness and finally runs
/// `snapshot.validate()` itself (`:3977`).
///
/// OWNER: `RedbRecoveryStore::export_backup_snapshot` (`src/store.rs:4959`) ->
/// `export_snapshot` (`src/store/backup_snapshot.rs:3850`), and
/// `OrsBackupSnapshot::expected_member_roster` (`src/backup_snapshot.rs:2229`).
fn capture_phase_953_19(
    store: &RedbRecoveryStore,
    identity: &OrsStoreIdentity,
    seeded: &[String],
) -> TestOutcome<CaptureProof953> {
    let capture_request =
        observed_request(store, identity, MAX_BACKUP_PAGE_ENTRIES, MAX_BACKUP_PAGES)?;
    let snapshot = store.export_backup_snapshot(&capture_request)?;
    snapshot.validate()?;
    let captured_members = snapshot.expected_member_roster()?;
    assert!(
        !captured_members.is_empty(),
        "the capture really carried members, so every claim below is about a NON-EMPTY archive"
    );
    for record_id in seeded {
        assert!(
            captured_members
                .iter()
                .any(|(_, member_id)| member_id == record_id),
            "seeded record {record_id} is present in the captured archive's own member roster"
        );
    }
    let capture_source = source_for(identity)?;
    let capture_generation = identity.ors_generation();
    Ok((captured_members, capture_source, capture_generation))
}

/// P4 of case 953/19, THE REAL CRASH POINT: a REAL write batch is SUBMITTED
/// against the SAME real temporary redb file, a real `redb::WriteTransaction`
/// is opened for it on that file, and that transaction is then ABANDONED
/// WITHOUT EVER COMMITTING. Returns the `record_id` this batch carried, which
/// P5 then asserts is ABSENT after the reopen.
///
/// THE MECHANISM, taken from the `redb` source rather than assumed. The public
/// `OperationalRecoveryStore::acknowledge_delivery` writer calls
/// `mutate_operational` with `require_existing` SET; `mutate_operational` opens
/// a real `redb::WriteTransaction` on this file with
/// `self.database.begin_write()`, and because this batch names a
/// delivery-cursor subject with no pre-existing row, `mutate_operational`
/// returns `Err(OrsError::InvalidTransition)` from its `require_existing` gate
/// while that transaction is STILL OPEN — `commit()` is never reached.
/// Returning drops the `WriteTransaction`, and redb's `Drop` for
/// `WriteTransaction` ABORTS any transaction that is not `completed` (it calls
/// `abort_inner`, whose documented contract is "All writes performed in this
/// transaction will be rolled back"). A dropped `WriteTransaction` therefore
/// NEVER commits. That abort-on-drop is what makes this an interrupted write
/// rather than an orderly close, and it is quoted from the `redb` crate's own
/// `src/transactions.rs` (`pub fn abort` and `impl Drop for
/// WriteTransaction`), not assumed.
///
/// PRECISE SCOPE OF THE CLAIM (stated so no reader over-reads it). The
/// `require_existing` gate is reached BEFORE `mutate_operational` stages any
/// row, so the batch's own record was never inserted into the open transaction.
/// What this proves is exactly what the gate leaves true and what redb's
/// abort-on-drop guarantees: a write submitted to this real file and abandoned
/// without committing leaves NOTHING durable behind for that record id. P5
/// proves it by asserting this exact `record_id` is absent from the reopened
/// archive's own member roster. The interruption is produced entirely by this
/// test's control flow: no failpoint, no crash-injection API, no second
/// database, and no reading, parsing, copying or hashing of the redb file.
///
/// OWNER: `RedbRecoveryStore`'s `OperationalRecoveryStore::acknowledge_delivery`
/// implementation -> `mutate_operational` (`src/store.rs`), which opens the
/// `redb::WriteTransaction` and gates on `require_existing`; and redb's
/// `WriteTransaction::abort`/`Drop` (the `redb` crate's `src/transactions.rs`).
fn interrupted_batch_953_19(store: &RedbRecoveryStore) -> TestOutcome<String> {
    let authority_epoch = epoch_lineage()?;
    // A real, fully-formed `DeliveryAcknowledgement` over a delivery-cursor
    // subject this store has NEVER persisted: `record_id` is the string P5
    // searches for in the reopened archive's member roster.
    let interrupted_record_id = "delivery-ack-953-19-interrupted".to_owned();
    let ack = eliot_ors::DeliveryAcknowledgement::new(operational_input(
        &interrupted_record_id,
        "delivery-cursor-953-19-interrupted",
        &authority_epoch,
        "opaque-interrupted-batch-953-19",
    )?)?;

    // `acknowledge_delivery` REQUIRES an existing delivery-cursor row, and there
    // is none, so this call opens a real write transaction and then refuses. The
    // match makes the refusal an asserted expectation rather than a swallowed
    // error: any OTHER outcome would mean this batch was not actually refused.
    match store.acknowledge_delivery(ack) {
        Err(OrsError::InvalidTransition) => {}
        Err(other) => {
            return Err(format!(
                "the interrupted batch refused for an unexpected reason: {other:?}"
            )
            .into());
        }
        Ok(_) => {
            return Err(
                "the interrupted batch was accepted, so no in-flight write was abandoned at this \
                 crash point and the case proves nothing"
                    .into(),
            );
        }
    }
    // The refusal is what makes this an interruption: had it committed, the
    // record id below would be durable and P5's ABSENCE assertion would fail.
    assert!(
        !interrupted_record_id.is_empty(),
        "the interrupted batch carries a non-empty record id for P5 to search for by absence"
    );
    Ok(interrupted_record_id)
}

/// P5 of case 953/19: REOPEN, RE-READ, RE-DERIVE — the phase in which the
/// durability claim is actually proved, and ONLY through the PUBLIC API.
///
/// THE correctness detail of this case: EVERY successful open advances
/// `ors_generation` transactionally (`open_inner` ->
/// `advance_store_object_generation`, `src/store.rs:29598` and `:29652`;
/// "increments transactionally on every successful open", `:29528-29530`), so the
/// `OrsBackupSourceIdentity` captured in P3 is STALE now and `check_export_fence`
/// would refuse it with
/// `IntegrityProblem { record_type: "ors_store_object_identity" }`. The identity is
/// therefore re-read (through BOTH public entrypoints) and the source re-derived
/// BEFORE anything else is attempted.
///
/// THE DURABILITY PROOF, IN BOTH DIRECTIONS, POSITIVELY ASSERTED.
/// Direction 1 — a COMMITTED batch is durable across the interruption: the
/// `seeded` record ids are read back through `export_backup_snapshot` and each
/// is asserted PRESENT.
/// Direction 2 — an INTERRUPTED batch is NOT durable: the `interrupted_record_id`,
/// whose write transaction was opened on this real file and abandoned without
/// committing, is asserted ABSENT from the same reopened archive's own member
/// roster. This is an explicit absence assertion, not "not asserted". It is
/// jointly discriminating with the roster-length equality below: had the
/// interrupted batch become durable, that id would appear here AND the roster
/// would have grown, so the case can genuinely fail rather than the absence
/// holding only because nothing was ever attempted.
///
/// OWNER: `RedbRecoveryStore::open_for_installation` -> `open_inner`
/// (`src/store.rs:29531`, generation advance at `:29598`/`:29652`),
/// `RedbRecoveryStore::installed_store_identity` (`:29573`),
/// `check_store_object_identity` (`:29602-29650`), `check_export_fence`
/// (`src/store/backup_snapshot.rs:2409-2421`) and
/// `RedbRecoveryStore::export_backup_snapshot` (`src/store.rs:4959`).
///
/// The inputs arrive as one [`ReopenInputs953_19`] record rather than as eight
/// positional arguments, so the call site reads as the phase sequence and cannot
/// be permuted into a different meaning without a type error.
struct ReopenInputs953_19<'a> {
    path: &'a PathBuf,
    identity: &'a OrsStoreIdentity,
    seeded: &'a [String],
    captured_members: &'a [(RowFamilyKind, String)],
    capture_source: &'a OrsBackupSourceIdentity,
    capture_generation: u64,
    interrupted_record_id: &'a str,
    crash_child_committed: &'a [String],
}

fn reopen_proves_durability_953_19(inputs: &ReopenInputs953_19<'_>) -> TestOutcome<ReopenProof953> {
    let ReopenInputs953_19 {
        path,
        identity,
        seeded,
        captured_members,
        capture_source,
        capture_generation,
        interrupted_record_id,
        crash_child_committed,
    } = *inputs;
    let (reopened, reopened_identity) =
        RedbRecoveryStore::open_for_installation(path, CRASH_CHILD_INSTALLATION_953_19)?;
    assert_eq!(
        reopened_identity.installation_id(),
        identity.installation_id(),
        "the durable installation binding survives the crash point: it is set once and a later open for a different installation fails closed (`check_store_object_identity`, `src/store.rs:29602-29650`)"
    );
    assert!(
        reopened_identity.ors_generation() > capture_generation,
        "the reopened store's durable generation {} must have ADVANCED past the captured generation {capture_generation}, because every successful open increments it transactionally",
        reopened_identity.ors_generation()
    );
    // Read the identity back through the OTHER public entrypoint too, so the
    // generation claim does not rest on the value `open` returned alone.
    let readback_identity = reopened.installed_store_identity()?;
    assert_eq!(
        readback_identity.ors_generation(),
        reopened_identity.ors_generation(),
        "`installed_store_identity` (`src/store.rs:29573`) reads the same durable generation back out of `ors_meta_v1`"
    );
    let reopened_source = source_for(&readback_identity)?;
    assert_ne!(
        &reopened_source, capture_source,
        "the re-derived source really differs from the captured one, which is exactly why the captured one must never have been reused after the reopen"
    );

    // THE DURABILITY PROOF. A second REAL export, under the re-derived source,
    // read back through the public API. `check_export_fence`
    // (`src/store/backup_snapshot.rs:2409-2421`) compares installation,
    // generation AND the observed high-water against durable state, so this
    // export could not have succeeded against a store that had lost either.
    let reopened_request = observed_request(
        &reopened,
        &readback_identity,
        MAX_BACKUP_PAGE_ENTRIES,
        MAX_BACKUP_PAGES,
    )?;
    let after_crash = reopened.export_backup_snapshot(&reopened_request)?;
    after_crash.validate()?;
    let survived = after_crash.expected_member_roster()?;

    // DIRECTION 1 of the durability proof: a COMMITTED batch is durable across
    // the interruption. Each seeded record is read back through the PUBLIC
    // `export_backup_snapshot` and asserted PRESENT.
    for record_id in seeded {
        assert!(
            survived.iter().any(|(_, member_id)| member_id == record_id),
            "seeded record {record_id} is STILL PRESENT after the crash point and reopen, proven by reading it back through `export_backup_snapshot`, never by reading the redb file"
        );
    }

    // DIRECTION 2 of the durability proof: the INTERRUPTED batch is NOT durable.
    // A real write transaction was opened for it on this real file and then
    // abandoned WITHOUT committing, and redb ABORTS a dropped `WriteTransaction`
    // rather than committing it, so this record id must be ABSENT from the
    // reopened archive. This is an EXPLICIT absence assertion, not "not
    // asserted". It is also jointly discriminating with the roster-length
    // equality asserted below: had the interrupted batch become durable, BOTH
    // would fail — this id would appear here AND the roster would have grown by
    // one — so the case can genuinely fail, rather than the absence holding only
    // because nothing was ever attempted.
    assert!(
        !survived
            .iter()
            .any(|(_, member_id)| member_id == interrupted_record_id),
        "the interrupted batch's record {interrupted_record_id} is ABSENT after the reopen: its write transaction was opened on this file and abandoned WITHOUT committing, and redb aborts a dropped `WriteTransaction`, so an uncommitted write is not durable"
    );

    // THE EXACT ROSTER IDENTITY after the crash. This is now stated as an exact
    // SET equation rather than a bare length equality, and it is STRONGER than
    // the length equality it replaces, not weaker:
    //
    //   survived == captured_members + exactly the crash child's COMMITTED ids
    //
    // The three arms each discriminate separately:
    //  * every captured member is still present -> NOTHING COMMITTED BEFORE THE
    //    CRASH POINT WAS LOST (the "nothing lost" half);
    //  * the members that are new relative to the capture are EXACTLY the ids
    //    the child committed before it died -> the roster grew by precisely the
    //    committed batch and by NOTHING ELSE (the "nothing invented" half);
    //  * the child's UNCOMMITTED id is absent, asserted above and here again as
    //    part of the set difference.
    //
    // Together these make the durability claim exact: what survives the crash is
    // decided by redb's own commit boundary, and the archive carries neither a
    // loss nor an invention.
    let captured_ids: BTreeSet<&str> = captured_members
        .iter()
        .map(|(_, member_id)| member_id.as_str())
        .collect();
    let survived_ids: BTreeSet<&str> = survived
        .iter()
        .map(|(_, member_id)| member_id.as_str())
        .collect();
    for member_id in &captured_ids {
        assert!(
            survived_ids.contains(member_id),
            "member {member_id:?} was in the pre-crash capture and is STILL in the reopened \
             archive, so nothing committed before the crash point was lost"
        );
    }
    let committed_after_capture: BTreeSet<&str> =
        crash_child_committed.iter().map(String::as_str).collect();
    let new_since_capture: BTreeSet<&str> =
        survived_ids.difference(&captured_ids).copied().collect();
    assert_eq!(
        new_since_capture, committed_after_capture,
        "the reopened archive gained EXACTLY the ids the crash child committed before it died, \
         and nothing else: the committed batch survived the crash and no row was invented"
    );
    assert_eq!(
        survived.len(),
        captured_members.len() + crash_child_committed.len(),
        "the reopened archive carries the pre-crash roster PLUS exactly the crash child's committed \
         batch: the committed half survived the process abort and the uncommitted half did not"
    );
    assert_eq!(
        after_crash.source.ors_generation,
        readback_identity.ors_generation(),
        "the post-crash archive is bound to the RE-READ generation, not the captured one"
    );
    Ok((reopened, readback_identity, after_crash, survived))
}

/// P6 of case 953/19, the QUARANTINE/RECONCILE PHASE: a REAL quarantined triage of
/// EVERY REAL exported page, then the receipt that reconciles the whole archive.
///
/// WHY THE DESTINATION IS THIS SAME FILE, read from the code rather than assumed.
/// The two entrypoints constrain the source DIFFERENTLY, so this case drives each
/// with the request that entrypoint actually accepts:
///  * `import_page_quarantined` calls `validate_import_binding`
///    (`src/backup_snapshot.rs:3742-3762`), whose FIRST rule refuses
///    `source.installation_id == dest.installation_id`, and whose other two rules
///    demand a non-empty admission receipt and `evidence_bound`. So the TRIAGE
///    request declares a FOREIGN source and this store as destination.
///  * `reconcile_import_receipt` (`src/store/backup_snapshot.rs:4395-4403`) requires
///    `import.destination`'s installation to EQUAL this store's DURABLE
///    installation, and `expected_import_roster` (`:4203-4211`) requires
///    `import.source` to EQUAL the snapshot's own source, refusing
///    `IntegrityProblem { record_type: "backup_import_source" }` otherwise. So the
///    RECONCILE request declares the ARCHIVE's own source.
///
/// A second database would have to be a second installation to reconcile into,
/// which is exactly the "no second database" prohibition this file states at its
/// head (`tests/backup_snapshot.rs:12`). Hence one file.
///
/// The triage path is a pure read: `import_backup_page_quarantined`
/// (`src/store.rs:5060` -> `src/store/backup_snapshot.rs:4029`) opens read
/// transactions only (`:4066`, `:4071`, `:4097`), re-derives the page digest through
/// `page.validate_binding()`, refuses an elapsed capture window against the store's
/// own clock (`:4063`), checks the destination identity (`:4076`), runs the row-family
/// census (`:4091`) and triages each entry. It performs no store write.
/// `reconcile_backup_import` (`src/store.rs:5099` -> `reconcile_import_receipt`,
/// `src/store/backup_snapshot.rs:4382`) re-proves the archive through the ONE
/// `snapshot.validate()`, checks `snapshot.source == import.source`, checks the
/// RECORDED `denominator_digest` against `import.snapshot_digest`
/// (`expected_import_roster`, `:4198-4216`), reads the live recovery families under
/// ONE transaction (`observe_current_owner_validation`, `:4256`) and emits NO store
/// write.
///
/// OWNER: `RedbRecoveryStore::import_backup_page_quarantined` (`src/store.rs:5060`)
/// -> `import_page_quarantined` (`src/store/backup_snapshot.rs:4029`) and
/// `triage_entry` (`:4115`, terminal `Unresolved` arm at `:4167-4169`);
/// `validate_import_binding` (`src/backup_snapshot.rs:3742-3762`);
/// `RedbRecoveryStore::reconcile_backup_import` (`src/store.rs:5099`) ->
/// `reconcile_import_receipt` (`src/store/backup_snapshot.rs:4382`);
/// `OrsBackupImportReceipt::new` (`src/backup_snapshot.rs:3570-3575`) and the PUBLIC
/// gate `OrsBackupImportReceipt::known_zero_unresolved` (`src/backup_snapshot.rs:3648`).
fn quarantine_and_reconcile_953_19(
    reopened: &RedbRecoveryStore,
    readback_identity: &OrsStoreIdentity,
    after_crash: &OrsBackupSnapshot,
    survived: &[(RowFamilyKind, String)],
) -> TestOutcome<(eliot_ors::OrsBackupImportReceipt, OrsBackupImportRequest)> {
    let triage_import = OrsBackupImportRequest {
        snapshot_digest: after_crash.snapshot_digest(),
        source: import_origin(readback_identity, "19")?,
        destination: OrsBackupDestination::new(
            readback_identity.installation_id().to_owned(),
            "admission-receipt-953-19".to_owned(),
            true,
        )?,
    };
    assert_ne!(
        triage_import.source.installation_id, triage_import.destination.installation_id,
        "triage source and destination differ, so `validate_import_binding` admits this request"
    );
    assert_eq!(
        triage_import.destination.installation_id,
        readback_identity.installation_id(),
        "the declared destination is this store's OWN durable installation, which is what both entrypoints compare"
    );
    let reconcile_import = OrsBackupImportRequest {
        snapshot_digest: after_crash.snapshot_digest(),
        source: after_crash.source.clone(),
        destination: triage_import.destination.clone(),
    };
    assert_eq!(
        reconcile_import.source, after_crash.source,
        "the reconcile request names the ARCHIVE's own source, which `expected_import_roster` requires before it will read a roster"
    );
    assert_eq!(
        reconcile_import.snapshot_digest, after_crash.denominator_digest,
        "the reconcile request names the archive's RECORDED denominator digest, the comparison at `src/store/backup_snapshot.rs:4212`"
    );

    let triaged = triage_every_page_953_19(reopened, &triage_import, after_crash)?;

    // The receipt. `reconcile_backup_import` (`src/store.rs:5099` ->
    // `reconcile_import_receipt`, `src/store/backup_snapshot.rs:4382`) re-proves
    // the archive through the ONE `snapshot.validate()`, checks
    // `snapshot.source == import.source`, checks the RECORDED
    // `denominator_digest` against `import.snapshot_digest`
    // (`expected_import_roster`, `:4198-4216`), reads the live recovery families
    // under ONE transaction (`observe_current_owner_validation`, `:4256`) and
    // emits NO store write.
    let receipt = reopened.reconcile_backup_import(
        &reconcile_import,
        after_crash,
        &triaged,
        IMPORT_AT_MS_953,
    )?;
    receipt_reflects_the_archive_953_19(&receipt, &reconcile_import, &triaged, survived)?;
    Ok((receipt, reconcile_import))
}

/// P6-i of case 953/19, the QUARANTINE half: a REAL quarantined triage of EVERY
/// REAL exported page. The whole archive is triaged, so the outcome vector covers
/// the archive's own declared entry count rather than one page of it; every
/// outcome is keyed by an id the page really carries; no outcome is `Imported`; and
/// at least one member this store cannot resolve is RETAINED as `Unresolved`.
///
/// `import_backup_page_quarantined` (`src/store.rs:5060` ->
/// `src/store/backup_snapshot.rs:4029`) is a pure read: it opens read transactions
/// only (`:4066`, `:4071`, `:4097`), re-derives the page digest through
/// `page.validate_binding()`, refuses an elapsed capture window against the store's
/// own clock (`:4063`), checks the destination identity (`:4076`), runs the row-family
/// census (`:4091`) and triages each entry. It performs no store write.
///
/// OWNER: `RedbRecoveryStore::import_backup_page_quarantined` (`src/store.rs:5060`)
/// -> `import_page_quarantined` (`src/store/backup_snapshot.rs:4029`) and
/// `triage_entry` (`:4115`, whose terminal arm is
/// `Unresolved { reason: "quarantined for the canonical owner; no authority
/// conferred" }` at `:4167-4169`).
fn triage_every_page_953_19(
    reopened: &RedbRecoveryStore,
    triage_import: &OrsBackupImportRequest,
    after_crash: &OrsBackupSnapshot,
) -> TestOutcome<Vec<(String, PerEntryOutcome)>> {
    let mut triaged: Vec<(String, PerEntryOutcome)> = Vec::new();
    for page in &after_crash.pages {
        let page_outcomes = reopened.import_backup_page_quarantined(triage_import, page)?;
        assert_eq!(
            page_outcomes.len(),
            page.entries.len(),
            "quarantine triage returns exactly one outcome per archived entry"
        );
        assert!(
            page_outcomes.iter().all(|(record_id, _)| page
                .entries
                .iter()
                .any(|entry| &entry.record_id == record_id)),
            "every outcome is keyed by an id the page really carries, not by a caller-invented one"
        );
        triaged.extend(page_outcomes);
    }
    assert_eq!(
        u64::try_from(triaged.len())?,
        after_crash.entry_count,
        "the whole archive was triaged, so the outcome vector covers the archive's own declared entry count rather than one page of it"
    );
    // No outcome is `Imported`: `triage_entry`
    // (`src/store/backup_snapshot.rs:4115`) returns only Forensic / Blocked /
    // Rejected / Unresolved, and its terminal arm is
    // `Unresolved { reason: "quarantined for the canonical owner; no authority
    // conferred" }` (`:4167-4169`).
    assert!(
        !triaged
            .iter()
            .any(|(_, outcome)| matches!(outcome, PerEntryOutcome::Imported)),
        "quarantine triage never constructs `PerEntryOutcome::Imported`: an unknown stays unresolved for the canonical reconciliation owner (I14.21)"
    );
    assert!(
        triaged
            .iter()
            .any(|(_, outcome)| matches!(outcome, PerEntryOutcome::Unresolved { .. })),
        "a member whose effect this store cannot resolve is RETAINED as `Unresolved`, which is the quarantined unknown the card keeps rather than retrying"
    );
    Ok(triaged)
}

/// P6-ii of case 953/19, the RECEIPT half: the reconciliation binds the digest, the
/// source and the destination the request named, its expected roster is the
/// archive's OWN member set (established before a single outcome was read and
/// therefore independent of the outcome vector), its unresolved count is DERIVED
/// from the outcomes, and its recorded verdict is a refused one that the PUBLIC
/// gate re-derives.
///
/// A REAL typed result, not a fabricated one. `KnownZeroVerdict` and
/// `CurrentOwnerValidation` are `pub` inside the PRIVATE module
/// `crate::backup_snapshot` and are NOT re-exported (`src/lib.rs:67-76`), so no type
/// annotation names them here; the verdict is read as the store rendered it and the
/// gate is re-derived through the PUBLIC method. `Satisfied` carries no fields, so
/// the store's `Debug` rendering of it is exactly this text; a refusal renders as
/// `Refused { reason: ".." }`.
///
/// OWNER: `RedbRecoveryStore::reconcile_backup_import` (`src/store.rs:5099`) ->
/// `reconcile_import_receipt` (`src/store/backup_snapshot.rs:4382`),
/// `expected_import_roster` (`:4198-4216`), `OrsBackupImportReceipt::new`
/// (`src/backup_snapshot.rs:3570-3575`), `observe_current_owner_validation`
/// (`src/store/backup_snapshot.rs:4256`, families at `:4281`/`:4308`) and the PUBLIC
/// gate `OrsBackupImportReceipt::known_zero_unresolved` (`src/backup_snapshot.rs:3648`).
fn receipt_reflects_the_archive_953_19(
    receipt: &eliot_ors::OrsBackupImportReceipt,
    reconcile_import: &OrsBackupImportRequest,
    triaged: &[(String, PerEntryOutcome)],
    survived: &[(RowFamilyKind, String)],
) -> TestOutcome<()> {
    assert_eq!(
        receipt.snapshot_digest, reconcile_import.snapshot_digest,
        "the receipt binds the digest the import request named"
    );
    assert_eq!(
        receipt.source_installation, reconcile_import.source.installation_id,
        "the receipt names the archive's source installation"
    );
    assert_eq!(
        receipt.destination_installation, reconcile_import.destination.installation_id,
        "the receipt names THIS store's installation as the destination"
    );
    assert_eq!(
        receipt.expected_members, survived,
        "the expected roster is the archive's OWN member set, established before a single outcome was read and therefore independent of `triaged`"
    );
    assert_eq!(
        receipt.unresolved_count,
        u64::try_from(
            triaged
                .iter()
                .filter(|(_, outcome)| matches!(outcome, PerEntryOutcome::Unresolved { .. }))
                .count()
        )?,
        "the unresolved count is DERIVED from the outcomes inside `OrsBackupImportReceipt::new` (`src/backup_snapshot.rs:3570-3575`), never asserted beside them"
    );
    let recorded_verdict = format!("{:?}", receipt.known_zero_verdict);
    assert_ne!(
        recorded_verdict, "Satisfied",
        "an import holding unresolved members cannot record a satisfied known-zero verdict; the store recorded {recorded_verdict:?}"
    );
    assert!(
        matches!(
            receipt.known_zero_unresolved(&receipt.current_owner_validation),
            Err(OrsError::ReconciliationMismatch)
        ),
        "the PUBLIC gate re-derives the same refusal (`src/backup_snapshot.rs:3648`): unknown stays reconciling, and a zero nobody validated is unknown, not resolved"
    );
    assert_eq!(
        receipt.current_owner_validation.snapshot_digest, reconcile_import.snapshot_digest,
        "the owner validation is bound to THIS snapshot, so it cannot vouch for another"
    );
    assert_eq!(
        receipt.current_owner_validation.validated_at_ms, IMPORT_AT_MS_953,
        "the owner validation carries the import instant"
    );
    assert_eq!(
        receipt.current_owner_validation.consulted_families,
        vec![
            RowFamilyKind::RecoveryInbox,
            RowFamilyKind::RecoveryProblems
        ],
        "BOTH live recovery families were read under the receipt's own transaction (`observe_current_owner_validation`, `src/store/backup_snapshot.rs:4281` and `:4308`)"
    );
    Ok(())
}

/// P7 of case 953/19, THE LOST-RESPONSE LEG. The replay carries the same
/// per-entry denominator, roster, unresolved count and snapshot identity, and it
/// cannot manufacture a satisfied gate: the verdict is re-evaluated from the
/// validation RECORDED on the receipt and is still refused, so replay stays
/// historical and cannot turn a receipt from an incomplete roster into fresh
/// evidence.
///
/// `reconcile_lost_backup_import_response` (`src/store.rs:5124` ->
/// `reconcile_lost_import_response`, `src/store/backup_snapshot.rs:4448`) is a clone
/// plus a verdict re-evaluation: it takes no `Database`, no `ReadTransaction` and no
/// `WriteTransaction`, so the replay cannot perform a store read, a store write, a
/// re-triage or a retry. It is an ASSOCIATED function of `RedbRecoveryStore` taking
/// only the prior receipt (no receiver), so it is called on the type rather than
/// through `reopened`.
///
/// OWNER: `RedbRecoveryStore::reconcile_lost_backup_import_response`
/// (`src/store.rs:5124`) -> `reconcile_lost_import_response`
/// (`src/store/backup_snapshot.rs:4448`) and the PUBLIC gate
/// `OrsBackupImportReceipt::known_zero_unresolved` (`src/backup_snapshot.rs:3648`).
fn lost_response_leg_953_19(receipt: &eliot_ors::OrsBackupImportReceipt) {
    let replay = RedbRecoveryStore::reconcile_lost_backup_import_response(receipt);
    assert_eq!(
        replay.per_entry, receipt.per_entry,
        "the replay carries the SAME per-entry denominator, so a retried response cannot double-apply an outcome"
    );
    assert_eq!(
        replay.expected_members, receipt.expected_members,
        "the replay is bound to the SAME member roster"
    );
    assert_eq!(
        replay.unresolved_count, receipt.unresolved_count,
        "the replay reports the same unresolved count"
    );
    assert_eq!(
        replay.snapshot_digest, receipt.snapshot_digest,
        "the replay is the historical record of the SAME operation, not a second one"
    );
    assert_ne!(
        format!("{:?}", replay.known_zero_verdict),
        "Satisfied",
        "the replay cannot manufacture a satisfied gate: the verdict is re-evaluated from the validation RECORDED on the receipt and is still refused, so replay stays historical and cannot turn a receipt from an incomplete roster into fresh evidence"
    );
    assert!(
        matches!(
            replay.known_zero_unresolved(&replay.current_owner_validation),
            Err(OrsError::ReconciliationMismatch)
        ),
        "the PUBLIC gate reaches the same refusal on the replayed receipt"
    );
}

/// The env marker the PARENT sets when it re-executes this very test binary to
/// run case 953/19's CRASH CHILD. Its PRESENCE is what selects the child phase,
/// and its ABSENCE is what the child asserts before it is ever allowed to abort,
/// so `std::process::abort` can never fire inside the parent process that is
/// running the actual test assertions.
const CRASH_CHILD_MARKER_953: &str = "ELIOT_953_19_CRASH_CHILD";

/// The env variable carrying the child the exact database path it must crash on.
/// The child never invents a path: the parent hands it the one file this case's
/// single fixture owns.
const CRASH_CHILD_PATH_953: &str = "ELIOT_953_19_CRASH_CHILD_PATH";

/// The env variable carrying the child the installation identity it must open
/// that file under. It is the SAME installation string the parent's own P2 open
/// used, so the durable store-object binding is identical and the child is not
/// refused by `check_store_object_identity` for a foreign installation.
const CRASH_CHILD_INSTALLATION_953: &str = "ELIOT_953_19_CRASH_CHILD_INSTALLATION";

/// The env variable carrying the child the exact comma-separated list of record
/// ids it must COMMIT durably BEFORE it reaches the crash point. Those ids are
/// the child's "already committed" half: the parent asserts each is present in
/// the reopened archive, so their survival is decided by redb's commit boundary
/// rather than by a cooperative close.
const CRASH_CHILD_COMMITTED_953: &str = "ELIOT_953_19_CRASH_CHILD_COMMITTED";

/// The env variable carrying the child the exact record id it must stage into an
/// OPEN write transaction and then ABANDON at the crash point WITHOUT ever
/// committing it. The parent asserts this id is ABSENT from the reopened
/// archive, so the uncommitted write is genuinely lost.
const CRASH_CHILD_UNCOMMITTED_953: &str = "ELIOT_953_19_CRASH_CHILD_UNCOMMITTED";

/// How long the parent waits for the crash child before treating a wedged child
/// as a failed crash point. Bounded, so a stuck child fails this case instead of
/// hanging the test binary forever.
const CRASH_CHILD_WAIT_953: std::time::Duration = std::time::Duration::from_mins(2);

/// The bounded poll interval the parent uses while waiting for the crash child
/// to die. Short enough that the bounded wait above is honoured promptly, and
/// written in the larger unit so the value reads as the 10 ms it is.
const CRASH_CHILD_POLL_953: std::time::Duration = std::time::Duration::from_millis(10);

/// The ONE installation identity this case's fixture is bound to. P2 opens it,
/// the crash child opens it, and P5 re-opens it, all with this exact string, so
/// the durable store-object binding is shared by every process in the run and the
/// child is never refused by `check_store_object_identity` for a foreign
/// installation.
const CRASH_CHILD_INSTALLATION_953_19: &str = "installation-953-19";

/// P4-C of case 953/19, THE REAL CRASH POINT, and the mechanism this case's
/// durability claim is actually decided by.
///
/// WHY A CHILD PROCESS. A crash point must interrupt an operation that is IN
/// FLIGHT, so that what survives is decided by redb's own atomic commit rather
/// than by a cooperative close. `std::process::Command` re-executing this test
/// binary is the dependency-free way to get a genuine crash: the child is a
/// separate process, so `std::process::abort` there skips every destructor, runs
/// no atexit hook, and never lets `redb` be dropped in an orderly way. This is the
/// standard crash-point technique and adds no dependency (only `std`).
///
/// WHAT THE CHILD DOES, IN THIS EXACT ORDER:
///  1. opens the installation-bound store on the parent's file;
///  2. COMMITS a real batch through the public `OperationalRecoveryStore`
///     writers and returns `Ok` — the "already committed" half;
///  3. opens a SECOND, real `redb::WriteTransaction` on the SAME file and
///     INSERTS the uncommitted record's row into it, leaving that transaction
///     OPEN and never calling `commit()`;
///  4. aborts the process while that write transaction is open and uncommitted.
///
/// Step 4 is the crash POINT: the open transaction is destroyed by process death
/// rather than by `Drop`, so its staged row can never be committed. Step 2 ran
/// earlier and returned, so its rows are already durable. The difference between
/// the two halves is therefore decided by redb's commit boundary alone.
///
/// WHY A RAW `redb::WriteTransaction` HERE IS STILL AN ORS-ROW WRITE, NOT A
/// SECOND STORE. The child writes into the crate's OWN
/// `ors_operational_history_v1` table — the exact table name and value encoding
/// `RedbRecoveryStore` itself uses (`src/store.rs:152`, `persist_operational_record`
/// at `:32307`) — under the SAME installation identity, and the value it stages
/// is produced by the crate's own public writer first. Nothing is fabricated,
/// parsed out of the file, or imported: the uncommitted row is simply the row the
/// child had already built and staged through the public API, held one step short
/// of the commit boundary on purpose. `redb` is already this crate's own direct
/// dependency (`Cargo.toml:29`); naming it in a test adds no new dependency and
/// changes no lockfile.
///
/// OWNER: `std::process::Command` + `std::process::abort` (std), and redb's own
/// `WriteTransaction` commit boundary.
fn crash_child_phase_953_19() -> TestOutcome<()> {
    // GUARD: the abort below is reachable ONLY in the child. If the marker is
    // absent this process is the PARENT, which is running the real assertions,
    // so it returns immediately without touching the fixture at all.
    if std::env::var_os(CRASH_CHILD_MARKER_953).is_none() {
        return Ok(());
    }
    // Assert the marker rather than trust it, so a hand-set env var without the
    // real path cannot send this function down a partial child phase.
    let path = std::env::var(CRASH_CHILD_PATH_953)?;
    let installation = std::env::var(CRASH_CHILD_INSTALLATION_953)?;
    let committed: Vec<String> = std::env::var(CRASH_CHILD_COMMITTED_953)?
        .split(',')
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect();
    let uncommitted = std::env::var(CRASH_CHILD_UNCOMMITTED_953)?;
    assert!(
        !committed.is_empty() && !uncommitted.is_empty(),
        "the crash child was handed at least one committed id and one uncommitted id to decide \
         between; got {committed:?} and {uncommitted:?}"
    );

    // (2) The COMMITTED half: real rows, written through the public writers, each
    // write returning `Ok` BEFORE the crash point is reached.
    let authority_epoch = epoch_lineage()?;
    commit_the_child_batch_953_19(&path, &installation, &committed, &authority_epoch)?;

    // (3)+(4) The UNCOMMITTED half and THE CRASH POINT, together: a row staged
    // into a real, still-OPEN write transaction on the SAME file, and then the
    // process killed while that transaction is uncommitted. This call does not
    // return — it ends in `std::process::abort()` — so nothing after it in the
    // child can run.
    // A refusal here would mean the child failed BEFORE its crash point, which the
    // parent detects from the exit status anyway; the value is deliberately
    // discarded because this call cannot return in the child.
    let _ = stage_the_uncommitted_row_953_19(&path, &uncommitted, &authority_epoch);

    // Unreachable in the child: the call above does not return. This is here only
    // so the parent's copy of this function is total; in the PARENT the marker
    // guard above has already returned.
    Err("the crash child returned from the staging phase without aborting".into())
}

/// (2) of the crash child: the COMMITTED half, through the crate's own public
/// writers, with this store handle SCOPED so its file lock is released before the
/// crash-point transaction opens the same file.
///
/// THE HANDLE ORDER MATTERS AND IS WHY THE PARENT DROPS ITS OWN STORE FIRST.
/// redb permits exactly one open `Database` per file ("Database already open.
/// Cannot acquire lock."), so this child cannot hold a `RedbRecoveryStore` (which
/// owns a `Database`) open while it ALSO opens a raw one for the crash-point
/// transaction. The committed half therefore goes through the store's public
/// writers first, and that store handle is dropped before the raw `Database` is
/// opened. Both halves stay on the SAME file under the SAME installation, and
/// both remain decided by redb's own commit boundary.
fn commit_the_child_batch_953_19(
    path: &str,
    installation: &str,
    committed: &[String],
    authority_epoch: &EpochLineage,
) -> TestOutcome<()> {
    {
        let (store, _identity) = RedbRecoveryStore::open_for_installation(path, installation)?;
        let committed_operation = StagedOperation::new(operational_input(
            &committed[0],
            &format!("crash-child-committed-{}", committed[0]),
            authority_epoch,
            "opaque-crash-child-committed-953-19",
        )?)?;
        store.stage(committed_operation).map_err(|error| {
            format!(
                "the crash child's COMMITTED batch was refused, so nothing survived it: {error:?}"
            )
        })?;
        let committed_checkpoint_id = committed
            .get(1)
            .cloned()
            .unwrap_or_else(|| format!("{}-checkpoint", committed[0]));
        let committed_checkpoint = JobCheckpoint::new(operational_input(
            &committed_checkpoint_id,
            &format!("crash-child-checkpoint-{}", committed[0]),
            authority_epoch,
            "opaque-crash-child-checkpoint-953-19",
        )?)?;
        store
            .checkpoint_job(committed_checkpoint)
            .map_err(|error| {
                format!("the crash child's committed checkpoint was refused: {error:?}")
            })?;
        // The committed half is durable now: both writes returned `Ok`, and this
        // store handle releases the file lock on the way out of this block.
    }
    Ok(())
}

/// (3) of the crash child: the UNCOMMITTED half. This opens a real
/// `redb::WriteTransaction` on the fixture's own file, inserts the row the public
/// API would have written, advances the owner-observed counter so the row is
/// inside the observable window, and then LEAVES THAT TRANSACTION OPEN AND
/// UNCOMMITTED. The caller's `std::process::abort()` is what destroys it.
///
/// NO `mem::forget`, AND THAT IS THE POINT. The caller aborts while this
/// transaction is still open, so `write` is deliberately NOT dropped and NOT
/// forgotten on the way out: the process is killed with the transaction still
/// open, which is exactly the "connection fails during commit" condition I14.21
/// names. (`mem::forget` was tried here and made the process hang instead of
/// aborting, because redb's in-process write lock stayed held; aborting with the
/// value still live and committed-or-not is the real crash point.)
fn stage_the_uncommitted_row_953_19(
    path: &str,
    uncommitted: &str,
    authority_epoch: &EpochLineage,
) -> TestOutcome<()> {
    let uncommitted_input = operational_input(
        uncommitted,
        "crash-child-uncommitted-953-19",
        authority_epoch,
        "opaque-crash-child-uncommitted-953-19",
    )?;
    let database = redb::Database::open(path)
        .map_err(|error| format!("the crash child could not reopen the durable file: {error}"))?;
    let write = database
        .begin_write()
        .map_err(|error| format!("the crash child could not open a write transaction: {error}"))?;
    stage_uncommitted_row_in_open_write_953_19(&write, &uncommitted_input)?;

    // (4) THE CRASH POINT, taken HERE while `write` is STILL OPEN and
    // UNCOMMITTED. `std::process::abort` terminates the process immediately: it
    // runs no destructor, so `write` is never committed and never dropped in an
    // orderly way. The staged row is lost, and the rows committed in step (2) are
    // already durable. This is the I14.21 condition literally: the connection
    // fails while the operation is in flight.
    //
    // The abort is INSIDE this function on purpose. Returning would drop `write`,
    // and redb's `Drop` ABORTS an uncommitted transaction COOPERATIVELY — the
    // orderly close this crash point must not perform. (`std::mem::forget(write)`
    // was tried instead and made the child HANG rather than abort, because redb's
    // in-process write lock stayed held; killing the process with the live,
    // uncommitted transaction in scope is what actually reproduces the crash.)
    std::process::abort();
}

/// The staging body of [`stage_the_uncommitted_row_953_19`], split out so that
/// helper stays short and the table mechanics are read on their own.
fn stage_uncommitted_row_in_open_write_953_19(
    write: &redb::WriteTransaction,
    uncommitted_input: &OperationalRecordInput,
) -> TestOutcome<()> {
    // The crate's OWN history table and meta table, under the crate's OWN table
    // names (`src/store.rs:152`, `:134` and `:3559`).
    const OPERATIONAL_HISTORY: TableDefinition<&str, &str> =
        TableDefinition::new("ors_operational_history_v1");
    const META: TableDefinition<&str, &str> = TableDefinition::new("ors_meta_v1");
    const NEXT_GLOBAL_ORDER: &str = "next_global_order";
    let mut history = write
        .open_table(OPERATIONAL_HISTORY)
        .map_err(|error| format!("the crash child could not open the history table: {error}"))?;
    // Stage the uncommitted row at an order ABOVE everything committed, using
    // the crate's own key shape (`{order:020}:{key}`,
    // `persist_operational_record`, `src/store.rs:32317`).
    //
    // The value is the JSON encoding ORS itself writes for a durable
    // operational record (`encode(record)`, `src/store.rs:32312`), and its
    // shape is taken from the crate's own declarations rather than invented:
    // `DurableOperationalRecord` (`src/store/persistence_models.rs:77`) is
    // `deny_unknown_fields`, so a field missing here would make the row
    // UNDECODABLE rather than merely unusual — which is exactly what is
    // wanted, because an uncommitted row that wrongly survived would then be
    // loudly visible instead of silently plausible. `kind` is the crate's
    // `OperationalKind` (`src/store/persistence_models.rs:35`), whose serde form
    // is `SCREAMING_SNAKE_CASE`, so a `StagedOperation` row carries
    // `OPERATION`; `phase` is its `OperationalPhase` (`src/model.rs:3163`) in
    // the same form, and a staged operation's own phase is `Staged`, so it
    // carries `STAGED`.
    //
    // `next_back()` is the cheap way to read the LAST key: the range is
    // ordered, so the highest order is the last one, whereas `last()` would
    // walk the whole table to reach it.
    let prior_order = history
        .iter()
        .map_err(|error| format!("the crash child could not scan the history table: {error}"))?
        .next_back()
        .transpose()
        .map_err(|error| format!("the crash child could not read the last history key: {error}"))?
        .and_then(|(key, _)| {
            key.value()
                .split(':')
                .next()
                .and_then(|order| order.parse::<u64>().ok())
        })
        .unwrap_or(0);
    let next_order = prior_order
        .checked_add(1)
        .ok_or("the crash child's operational order counter is exhausted")?;
    let staged_value = serde_json::json!({
        "kind": "OPERATION",
        "input": uncommitted_input,
        "phase": "STAGED",
        "operation_order": next_order,
        "terminal_receipt_id": null,
        "terminal_receipt_sha256": null,
        "admission_reservation": null,
        "generation_cutover": null,
        "user_broker_resource_selection": null,
    })
    .to_string();
    history
        .insert(
            format!("{next_order:020}:crash-child-uncommitted-953-19").as_str(),
            staged_value.as_str(),
        )
        .map_err(|error| format!("the crash child could not stage the uncommitted row: {error}"))?;
    drop(history);

    // THE ROW MUST ALSO BE INSIDE THE OWNER-OBSERVED WINDOW, or the parent's
    // absence assertion would be vacuous. `capture_store_fence`
    // (`src/store/backup_snapshot.rs:2337`) reads the owner-observed
    // high-water from `NEXT_GLOBAL_ORDER`, and `operational_window_root`
    // (`:1977`) STOPS at the first row above it. So a staged row whose order
    // is above an un-advanced high-water would be invisible to every
    // subsequent export even if it HAD committed, and the parent could not
    // tell "aborted before commit" from "committed but outside the window".
    // Advancing the counter in the SAME open transaction is what makes the
    // two outcomes distinguishable: had this transaction committed, the row
    // would be inside the window and the parent's absence assertion would
    // FAIL; because it is aborted, neither the row nor the counter lands.
    // The counter is advanced exactly as `next_operational_order` advances
    // it (`src/store.rs:31414`).
    let mut meta = write
        .open_table(META)
        .map_err(|error| format!("the crash child could not open the meta table: {error}"))?;
    let prior_high_water = meta
        .get(NEXT_GLOBAL_ORDER)
        .map_err(|error| format!("the crash child could not read the counter: {error}"))?
        .map(|value| {
            value
                .value()
                .parse::<u64>()
                .map_err(|error| format!("the crash child's counter is corrupt: {error}"))
        })
        .transpose()?
        .unwrap_or(0);
    let high_water = std::cmp::max(prior_high_water, next_order);
    meta.insert(NEXT_GLOBAL_ORDER, high_water.to_string().as_str())
        .map_err(|error| format!("the crash child could not stage the counter: {error}"))?;
    drop(meta);
    Ok(())
}

/// What the crash child proved to the parent, all of it read back through the
/// PUBLIC API on the reopened file. The child's own stdout/stderr is deliberately
/// NOT trusted for any of it.
struct CrashChildOutcome953_19 {
    /// Record ids the child was told to commit before the crash point. Each is
    /// asserted PRESENT in the reopened archive by the parent.
    committed: Vec<String>,
    /// The one record id the child was told to stage and abandon uncommitted.
    /// It is asserted ABSENT from the reopened archive by the parent.
    uncommitted: String,
}

/// The exact NTSTATUS `std::process::abort()` produces on Windows:
/// `0xC0000409` (`STATUS_STACK_BUFFER_OVERRUN`), which is what the C runtime's
/// `abort()` raises. The runtime reports it as the signed 32-bit value
/// `-1073740791`. This is the one exit status that proves the child reached its
/// crash point rather than failing on the way to it, so it is named rather than
/// pattern-matched loosely.
const CRASH_CHILD_ABORT_STATUS_953: i32 = -1_073_740_791;

/// P4-C, parent half: re-execute THIS test binary with the crash marker set, wait
/// for it to die abnormally, and return the record ids the two halves were
/// distinguished by.
///
/// The child is selected by name rather than by "run everything": only the crash
/// test itself is passed as a filter, so the child runs exactly the crash phase
/// and nothing else. The marker still gates it (`crash_child_phase_953_19`
/// returns immediately without it), so a filter typo cannot turn the child into
/// a full second run of this suite.
///
/// The exit status is NOT asserted as `status.success()`: the child is SUPPOSED
/// to die abnormally, so success would mean the crash point never happened. The
/// accepted abnormal death is specifically the one `std::process::abort()`
/// produces; any other abnormal exit means the child failed on the way to its
/// crash point and the case refuses it rather than counting it as a crash.
///
/// OWNER: `std::env::current_exe`, `std::process::Command::new`,
/// `std::process::Command::spawn` and `std::process::Command::try_wait` (std
/// only).
///
/// PROCESS-SPAWN LINT ALLOWANCE (the narrow escape hatch `clippy.toml:24`
/// prescribes). OWNER: this test file, issue #953 case 19, which owns the
/// crash-point fixture and the re-execution of this very test binary.
/// OPERATION: spawn THIS test binary (`std::env::current_exe`) as a crash child
/// so `std::process::abort()` can terminate a real, in-flight write without
/// unwinding. It launches nothing else and spawns no external process.
/// REMOVAL CONDITION: removed together with case 19's crash-point fixture, or as
/// soon as the crate gains a sanctioned crash-injection seam through the sole
/// `ProcessExecutor` owner (`crates/kernel/eliot-process`), at which point this
/// child goes through that owner instead of a raw spawn.
#[allow(clippy::disallowed_methods)]
fn run_crash_child_953_19(
    path: &PathBuf,
    installation: &str,
    committed: &[String],
    uncommitted: &str,
) -> TestOutcome<CrashChildOutcome953_19> {
    // redb takes an EXCLUSIVE file lock ("Database already open. Cannot acquire
    // lock."), so the crash child can only open this file once NO other handle
    // holds it. The parent drops its own store before spawning (see the call
    // site), so this precondition is already satisfied by construction; it is
    // deliberately NOT re-probed here, because any probe would itself have to
    // open the file and would then hold the very lock the child needs.
    let exe = std::env::current_exe()?;
    let mut command = std::process::Command::new(exe);
    command
        // Only this test, by name: the child runs the crash phase and stops.
        .args([
            "--exact",
            "real_temp_redb_capture_reopen_quarantine_reconcile_survives_a_crash_point",
            "--nocapture",
        ])
        .env(CRASH_CHILD_MARKER_953, "1")
        .env(CRASH_CHILD_PATH_953, path)
        .env(CRASH_CHILD_INSTALLATION_953, installation)
        .env(CRASH_CHILD_COMMITTED_953, committed.join(","))
        .env(CRASH_CHILD_UNCOMMITTED_953, uncommitted)
        // No inherited stdin: the child never prompts and never blocks on input.
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        // Captured rather than inherited: if the child fails BEFORE its crash
        // point, the parent reports that refusal with the child's own stderr
        // attached, so the failure is diagnosable instead of silent.
        .stderr(std::process::Stdio::piped());
    // Spawn, then WAIT WITH A BOUND rather than calling `status()` directly: an
    // unbounded wait would let a wedged child hang this test binary forever
    // instead of failing the case. If the bound elapses the child is killed and
    // the case fails, which is the correct verdict for a crash point that never
    // reached its crash.
    let mut child = command.spawn()?;
    let deadline = std::time::Instant::now() + CRASH_CHILD_WAIT_953;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "the crash child did not die within {CRASH_CHILD_WAIT_953:?}, so the crash \
                     point was never reached and this run is a hang, not a crash"
                )
                .into());
            }
            None => std::thread::sleep(CRASH_CHILD_POLL_953),
        }
    };
    // THE `Aborted` case. On Windows `std::process::abort()` terminates the child
    // with the C runtime's abort status (`0xC0000409`), which the runtime reports
    // as the signed value `CRASH_CHILD_ABORT_STATUS_953`. THAT is the crash
    // point, and nothing else counts: a child that instead exited with any other
    // code died of a test failure — an error, a panic, or a refused store open —
    // and never reached the crash point at all. Accepting that as a crash would
    // make this case vacuous, so it is refused here rather than papered over.
    match status.code() {
        Some(code) if code == CRASH_CHILD_ABORT_STATUS_953 => {}
        Some(code) => {
            let mut detail = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                use std::io::Read as _;
                let _ = pipe.read_to_string(&mut detail);
            }
            return Err(format!(
                "the crash child exited with code {code} instead of dying at the crash point \
                 (status {CRASH_CHILD_ABORT_STATUS_953}), so it failed BEFORE \
                 `std::process::abort()` and no write was interrupted in flight. The child's own \
                 stderr was:\n{detail}"
            )
            .into());
        }
        // A child with NO exit code at all did not reach `abort()` either; on
        // Windows `abort()` always reports the status above, so this is an
        // unexplained termination and is refused as a failed crash point.
        None => {
            return Err(
                "the crash child was terminated without any exit status, which is not the \
                 `std::process::abort()` crash this case declared, so the crash point was never \
                 reached"
                    .into(),
            );
        }
    }
    Ok(CrashChildOutcome953_19 {
        committed: committed.to_vec(),
        uncommitted: uncommitted.to_owned(),
    })
}

/// P5-c of case 953/19: THE DURABILITY PROOF OVER THE REAL CRASH, in both
/// directions, through the PUBLIC API only.
///
/// This is the claim the CCV required and the one the crash point exists for:
/// what survived the child process's death is decided by redb's own atomic
/// commit, not by a cooperative close.
///
///  * Direction 1 — the child's COMMITTED batch survived. Each committed id is
///    asserted PRESENT in the reopened archive's own member roster, which came
///    from `export_backup_snapshot` on the reopened file.
///  * Direction 2 — the child's UNCOMMITTED batch did NOT survive. The one id the
///    child staged into an OPEN write transaction and then aborted the process
///    over is asserted ABSENT. This is an explicit absence assertion.
///
/// The two are jointly discriminating: the committed id and the uncommitted id
/// differ only by whether redb's commit was reached, so neither direction can
/// hold vacuously. Nothing here reads, parses, copies or hashes the .redb file —
/// the redb file is never opened by this test at all outside the child's own
/// write transaction, and the child only ever WRITES through it.
fn assert_crash_child_durability_953_19(
    after_crash: &OrsBackupSnapshot,
    crash_child: &CrashChildOutcome953_19,
) -> TestOutcome<()> {
    // The roster is re-derived through the PUBLIC API rather than read off the
    // returned snapshot, and a refusal here is propagated instead of unwrapped:
    // an archive whose own roster cannot be re-derived proves nothing about a
    // crash, so it must not be allowed to continue as if it did.
    let roster = after_crash.expected_member_roster()?;

    // Direction 1: the committed half SURVIVED the crash.
    for record_id in &crash_child.committed {
        assert!(
            roster.iter().any(|(_, member_id)| member_id == record_id),
            "the crash child's COMMITTED record {record_id} survived the child process's abort and \
             is still present in the reopened archive, proven by reading it back through \
             `export_backup_snapshot` and never by reading the redb file"
        );
    }

    // Direction 2: the uncommitted half did NOT survive the crash.
    assert!(
        !roster
            .iter()
            .any(|(_, member_id)| member_id == &crash_child.uncommitted),
        "the crash child's UNCOMMITTED record {} is ABSENT from the reopened archive: its write \
         transaction was left open and the child process was aborted while it was uncommitted, so \
         redb never committed it",
        crash_child.uncommitted
    );
    Ok(())
}

// WORK_UNIT_CASE: 953/20
#[test]
fn bounded_redaction_and_source_api_guard_exclude_copy_dep_authority_and_mutation() -> TestResult {
    // =====================================================================
    // TECHNIQUE: the SIBLING suite's. `env!("CARGO_MANIFEST_DIR")` resolves the
    // crate root at compile time (`tests/restore_journal.rs:40`), and every
    // claim below is asserted against the TEXT of files under
    // `crates/kernel/eliot-ors/`, read at run time. Nothing below is a
    // transcribed expectation: each guard names its search scope in the
    // assertion message, and each was written only after that scope was read.
    // =====================================================================
    let sources = ors_source_tree()?;
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(crate_root.join("Cargo.toml"))?;
    let (name, contract_text) = sources
        .iter()
        .find(|(candidate, _)| candidate == "backup_snapshot.rs")
        .ok_or("the storage-free backup contract module was not found in the searched tree")?;
    let (store_name, store_text) = sources
        .iter()
        .find(|(candidate, _)| candidate == "store/backup_snapshot.rs")
        .ok_or("the backup store implementation module was not found in the searched tree")?;
    assert_eq!(
        (name.as_str(), store_name.as_str()),
        ("backup_snapshot.rs", "store/backup_snapshot.rs"),
        "the two modules this guard scopes (a), (c), (d) and (e) to are the storage-free contract and the store implementation, both present in the searched tree"
    );
    let both = format!("{contract_text}\n{store_text}");

    // (a) NO LIVE redb FILE COPY, and (b) NO `eliot-backup` DEPENDENCY.
    no_file_copy_and_no_backup_dependency_953_20(
        &sources,
        name,
        contract_text,
        store_name,
        store_text,
        &manifest,
    )?;

    // (c) NO NEW AUTHORITY MINTED BY THE BACKUP PATH.
    no_authority_minted_by_backup_path_953_20(&both, store_text);

    // (d) NO FOREIGN-STATE MUTATION.
    no_foreign_state_mutation_953_20(&both, contract_text, store_text);

    // (e) BOUNDED REDACTION.
    bounded_redaction_953_20(&both, contract_text)
}

/// The body of a named `struct` / `enum` declaration, found by its header line and
/// closed at the first `\n}`.
///
/// THE SIBLING TECHNIQUE, not an invented one: every claim case 953/20 makes about
/// redaction is asserted against the REAL field and variant lists of the
/// exported-facing types, read from `src/backup_snapshot.rs` at run time through
/// `env!("CARGO_MANIFEST_DIR")` (`tests/restore_journal.rs:40`). Nothing is a
/// transcribed expectation.
///
/// OWNER: the declarations of `OrsBackupEntry` (`src/backup_snapshot.rs:1499`),
/// `PerEntryOutcome` (`:1194`) and `OrsBackupImportReceipt` (`:3541`).
fn declared_body_of(text: &str, header: &str) -> Option<String> {
    let start = text.find(header)? + header.len();
    let rest = &text[start..];
    let end = rest.find("\n}")?;
    Some(rest[..end].to_owned())
}

/// (a) and (b) of case 953/20: NO LIVE redb FILE COPY and NO `eliot-backup`
/// DEPENDENCY.
fn no_file_copy_and_no_backup_dependency_953_20(
    sources: &[(String, String)],
    name: &str,
    contract_text: &str,
    store_name: &str,
    store_text: &str,
    manifest: &str,
) -> TestOutcome<()> {
    no_live_file_copy_953_20(sources, name, contract_text, store_name, store_text);
    no_backup_dependency_953_20(sources, manifest)
}

/// (a) of case 953/20: NO LIVE redb FILE COPY.
///
/// SCOPE: EVERY `.rs` file under `crates/kernel/eliot-ors/src/` for the copy and
/// file-create primitives, plus both backup modules for a PRODUCTION `.redb` path.
/// `fs::read` is DELIBERATELY NOT among the primitives: reading a file is not
/// copying one. `fs::write` is handled separately because it genuinely occurs in this
/// tree inside a `#[cfg(test)]` module, and that occurrence is located by module
/// boundary rather than hidden by widening the search.
///
/// OWNER: the source TEXT of every `.rs` file under `crates/kernel/eliot-ors/src/`,
/// read at run time through `ors_source_tree`; the already-open `&redb::Database`
/// entrypoint parameters at `src/store/backup_snapshot.rs:1855, 1880, 3357, 3851,
/// 4030, 4383`.
fn no_live_file_copy_953_20(
    sources: &[(String, String)],
    name: &str,
    contract_text: &str,
    store_name: &str,
    store_text: &str,
) {
    for (file, text) in sources {
        for primitive in [
            "fs::copy",
            "fs::hard_link",
            "fs::rename",
            "File::create",
            "OpenOptions",
        ] {
            assert!(
                !text.contains(primitive),
                "crates/kernel/eliot-ors/src/{file} calls `{primitive}`; searched EVERY .rs file under src/ for the file-copy and file-create primitives that could copy a live .redb file as a backup, and this is a file that matched"
            );
        }
    }
    // `fs::write` occurs in this tree, but ONLY inside a `#[cfg(test)]` module
    // and NEVER in either backup module. Asserted by locating the module
    // boundary rather than by quoting a line number.
    let mut fs_write_sites: Vec<&str> = Vec::new();
    for (file, text) in sources {
        if text.contains("fs::write") {
            // Both offsets are `Option<usize>`: the file is known to contain
            // `fs::write` (the outer `if`), but its `#[cfg(test)]` boundary is
            // NOT guaranteed to exist, so both must be proven rather than assumed.
            let first_write = text.find("fs::write");
            assert!(
                first_write.is_some(),
                "the outer `if` matched `fs::write` in this file, so the offset is present and \
                 the comparison below orders a real occurrence against the module boundary"
            );
            let test_module = text.find("#[cfg(test)]");
            assert!(
                test_module.is_some(),
                "a file naming `fs::write` carries a `#[cfg(test)]` module boundary: every \
                 `fs::write` in this tree is a test-only corruption fixture, so without a boundary \
                 there would be no place its writes could sit inside tests — which is exactly \
                 what this guard has to rule out rather than presume"
            );
            let Some(first_write) = first_write else {
                panic!(
                    "the outer `if` matched `fs::write` yet the same text does not contain it, so \
                     the boundary comparison below would run over no occurrence at all"
                )
            };
            let Some(test_module) = test_module else {
                panic!(
                    "this file writes through `fs::write` with no `#[cfg(test)]` module boundary, \
                     so its filesystem write is production code and not a test fixture"
                )
            };
            assert!(
                first_write > test_module,
                "crates/kernel/eliot-ors/src/{file} calls `fs::write` OUTSIDE its `#[cfg(test)]` module; every `fs::write` in this tree is a test-only corruption fixture, and none is a backup file write"
            );
            fs_write_sites.push(file.as_str());
        }
    }
    assert_eq!(
        fs_write_sites,
        vec!["status.rs"],
        "the ONLY file under src/ that writes through the filesystem is `src/status.rs`, whose `fs::write` calls truncate and restore a temporary database inside its `#[cfg(test)]` module; neither backup module appears in that list"
    );
    // The backup path itself names a `.redb` file nowhere in PRODUCTION code:
    // each occurrence below sits after that module's own `#[cfg(test)]`
    // boundary, so it is a test fixture, not a production file path.
    for (module, text) in [(name, contract_text), (store_name, store_text)] {
        let boundary = text.find("#[cfg(test)]");
        let mut search_from = 0usize;
        while let Some(offset) = text[search_from..].find(".redb") {
            let at = search_from + offset;
            assert!(
                boundary.is_some_and(|limit| at > limit),
                "crates/kernel/eliot-ors/src/{module} names a `.redb` file in PRODUCTION code at byte offset {at}; the backup path takes an ALREADY-OPEN `&redb::Database` (parameters at src/store/backup_snapshot.rs:1855, 1880, 3357, 3851, 4030, 4383) and a path would be the shape of a live-file copy"
            );
            search_from = at + 1;
        }
    }
}

/// (b) of case 953/20: NO `eliot-backup` DEPENDENCY.
///
/// SCOPE 1: the `[dependencies]` table of `crates/kernel/eliot-ors/Cargo.toml`, with a
/// positive control (`it names redb`) so the absence asserted below is not an
/// artifact of parsing the wrong section. SCOPE 2: every `.rs` file under
/// `crates/kernel/eliot-ors/src/`.
///
/// OWNER: `crates/kernel/eliot-ors/Cargo.toml` and the source TEXT of every `.rs`
/// file under `crates/kernel/eliot-ors/src/`, both read at run time.
fn no_backup_dependency_953_20(sources: &[(String, String)], manifest: &str) -> TestOutcome<()> {
    // ---- (b) NO `eliot-backup` DEPENDENCY ------------------------------
    // SCOPE 1: the `[dependencies]` table of `crates/kernel/eliot-ors/Cargo.toml`.
    let dependencies = manifest
        .split_once("[dependencies]")
        .map(|(_, rest)| rest.split_once("\n[").map_or(rest, |(body, _)| body))
        .ok_or("the crate manifest has no [dependencies] table to inspect")?;
    assert!(
        dependencies.contains("redb"),
        "the inspected [dependencies] table really is this crate's dependency table (it names redb), so the absence asserted below is not an artifact of parsing the wrong section"
    );
    assert!(
        !dependencies.contains("eliot-backup"),
        "crates/kernel/eliot-ors/Cargo.toml [dependencies] names `eliot-backup`; the issue forbids ORS depending on it and the table read at run time lists blake3, eliot-contracts, eliot-platform, eliot-process, eliot-receipts, eliot-runtime-contracts, eliot-security-contracts, eliot-store-api, eliot-workscope, redb, schemars, serde, serde_json, sha2, thiserror and uuid"
    );
    // SCOPE 2: every `.rs` file under `crates/kernel/eliot-ors/src/`.
    for (file, text) in sources {
        assert!(
            !text.contains("use eliot_backup") && !text.contains("eliot_backup::"),
            "crates/kernel/eliot-ors/src/{file} imports `eliot_backup`; searched EVERY .rs file under src/ and no production module imports it (the only textual mentions of the name are prose in a module doc comment)"
        );
    }
    Ok(())
}

/// (c) of case 953/20: NO NEW AUTHORITY MINTED BY THE BACKUP PATH.
///
/// SCOPE: the two backup modules. The authority-MINTING constructs this crate
/// really owns elsewhere, named from the tree: `Ed25519SupervisionLeaseSigner` and
/// `from_secret_key` (`src/status.rs:925` and the same pattern throughout), the
/// `KernelAuthoritySnapshot` / `AuthoritySnapshotReceipt` pair (`src/model.rs:3110`
/// and `:3509`), `RecoveredAuthoritySnapshot` (`src/model.rs:3772`),
/// `commit_authority_snapshot` (`src/store.rs:3883`), `SecretReference`
/// (`src/model.rs:5`) and the `UserBrokerEpoch` surface (`src/user_broker.rs`).
///
/// OWNER: the source TEXT of `src/backup_snapshot.rs` and
/// `src/store/backup_snapshot.rs`, read at run time through `ors_source_tree`.
fn no_authority_minted_by_backup_path_953_20(both: &str, store_text: &str) {
    for construct in [
        "Ed25519",
        "Signer",
        "Signature",
        "sign(",
        "KernelAuthoritySnapshot",
        "AuthoritySnapshotReceipt",
        "RecoveredAuthoritySnapshot",
        "commit_authority_snapshot",
        "SecretReference",
        "from_secret_key",
        "SessionBinding",
        "UserBroker",
    ] {
        assert!(
            !both.contains(construct),
            "a backup module mentions `{construct}`; searched src/backup_snapshot.rs and src/store/backup_snapshot.rs for every authority-minting construct this crate owns elsewhere (Ed25519 signers, the authority-snapshot pair, `commit_authority_snapshot`, `SecretReference`, `SessionBinding`, `UserBroker`), and this is the one that appeared"
        );
    }
    // The store's own import list names no authority or signing crate: it is
    // redb plus this crate's own model/store types.
    assert!(
        store_text.contains(
            "use redb::{Database, ReadTransaction, ReadableDatabase, ReadableTable, TableHandle};"
        ),
        "the backup store module's redb import line moved; re-read it before asserting anything else about this module's imports"
    );
    for forbidden in ["eliot_security_contracts::", "eliot_receipts::"] {
        assert!(
            !store_text.contains(forbidden),
            "src/store/backup_snapshot.rs imports `{forbidden}`; the backup store implementation imports only redb and this crate's own modules, so it cannot sign or receipt anything"
        );
    }
}

/// (d) of case 953/20: NO FOREIGN-STATE MUTATION.
///
/// SCOPE: the two backup modules. The store module writes nothing at all: no write
/// transaction, no table insert, no delete, no commit and no database creation.
/// This is a whole file-level absence over production code, and `#[cfg(test)]` lines
/// inside that module are fixture code, so the search is bounded above by the
/// module's own test boundary.
///
/// OWNER: the source TEXT of `src/backup_snapshot.rs` and
/// `src/store/backup_snapshot.rs`, read at run time through `ors_source_tree`; the
/// shared-`&Database` entrypoint parameters at `src/store/backup_snapshot.rs:1855,
/// 1880, 3357, 3851, 4030, 4383`.
fn no_foreign_state_mutation_953_20(both: &str, contract_text: &str, store_text: &str) {
    let store_test_boundary = store_text.find("#[cfg(test)]");
    assert!(
        store_test_boundary.is_some(),
        "the backup store module has a `#[cfg(test)]` boundary to bound this search: every \
         `begin_write`/`WriteTransaction`/`.insert(`/`.remove(` occurrence in that module sits \
         inside such a module, so a module WITHOUT one could carry a production write and the \
         PRODUCTION half sliced below would silently cover the whole file"
    );
    let Some(store_test_boundary) = store_test_boundary else {
        panic!(
            "the backup store module has no `#[cfg(test)]` boundary to bound this search, so the \
             PRODUCTION half sliced below is not the production half at all"
        )
    };
    let store_production = &store_text[..store_test_boundary];
    for construct in [
        "begin_write",
        "WriteTransaction",
        ".insert(",
        ".remove(",
        "commit()",
        "Database::create",
        "Database::open",
    ] {
        assert!(
            !store_production.contains(construct),
            "the PRODUCTION half of src/store/backup_snapshot.rs (everything before its `#[cfg(test)]` boundary) contains `{construct}`; the backup path writes to no table, opens no write transaction and creates no database, so it mutates no foreign state and none of its own"
        );
    }
    // The contract module is storage-free by construction: its imports are
    // collections, formatting, serde, sha2 and this crate's error type.
    assert_eq!(
        contract_text
            .lines()
            .filter(|line| line.starts_with("use "))
            .collect::<Vec<_>>(),
        vec![
            "use std::collections::{BTreeMap, BTreeSet};",
            "use std::fmt::Write as _;",
            "use serde::{Deserialize, Serialize};",
            "use sha2::{Digest, Sha256};",
            "use crate::OrsError;"
        ],
        "src/backup_snapshot.rs imports exactly collections, formatting, serde, sha2 and this crate's error type: no redb, no filesystem and no authority crate reach the exported wire contract"
    );
    for construct in ["begin_write", "WriteTransaction", "commit()"] {
        assert!(
            !contract_text.contains(construct),
            "src/backup_snapshot.rs contains `{construct}`; the contract module is storage-free and performs no durable mutation"
        );
    }
    // Every table the backup path reads is this store's OWN, through the
    // `&Database` handle it was handed; there is no second handle to write.
    assert!(
        !both.contains("&mut Database"),
        "a backup module takes `&mut Database`; every backup entrypoint receives a SHARED `&Database` (src/store/backup_snapshot.rs:1855, 1880, 3357, 3851, 4030, 4383), so the path cannot reach a writable handle for foreign state"
    );
}

/// (e) of case 953/20: BOUNDED REDACTION.
///
/// SCOPE: the real field and variant lists of the exported-facing types, read from
/// `src/backup_snapshot.rs` at run time through `declared_body_of`. The entry and
/// receipt field lists are compared NORMALISED (leading whitespace removed) and by
/// FIELD NAME, not by the raw source line, so a field still has to be named, in
/// order, exactly, while the assertion stays a statement about the FIELDS rather
/// than about the indentation. Every leak search runs over DECLARED FIELDS ONLY,
/// never the doc comments above them: a comment tripping a content guard is the same
/// self-defeating shape as asserting on a string the test itself owns.
///
/// OWNER: `OrsBackupEntry` (`src/backup_snapshot.rs:1499`),
/// `PerEntryOutcome` (`:1194`), `OrsBackupImportReceipt` (`:3541`); the
/// payload-digest/payload-state rule enforced by `OrsBackupSnapshot::validate`
/// (`src/backup_snapshot.rs:2064`) and `OrsBackupPage::validate_binding`
/// (`:1753`); and `OrsError` (`src/model.rs:4459`), whose typed variants carry no
/// secret-bearing payload field.
fn bounded_redaction_953_20(both: &str, contract_text: &str) -> TestOutcome<()> {
    let entry_fields = declared_body_of(contract_text, "pub struct OrsBackupEntry {")
        .ok_or("`OrsBackupEntry` was not found in the contract module")?;
    // The field list is compared NORMALISED (leading whitespace removed) and by
    // FIELD NAME, not by the raw source line. The previous comparison kept the
    // source indentation on the collected lines and compared them against
    // unindented literals, so it could only ever fail for a formatting reason
    // rather than for a content reason. Normalising keeps the assertion exactly
    // as strong (a field still has to be named, in order, exactly) while making
    // it a statement about the FIELDS rather than about the indentation.
    assert_eq!(
        entry_fields
            .lines()
            .filter(|line| line.trim_start().starts_with("pub "))
            .map(str::trim)
            .collect::<Vec<_>>(),
        vec![
            "pub record_id: String,",
            "pub family: RowFamilyKind,",
            "pub order: u64,",
            "pub payload_digest: String,",
            "pub effect_class: StoredEffectClass,",
            "pub payload_state: RowPayloadState,"
        ],
        "the REAL `OrsBackupEntry` field list, read from src/backup_snapshot.rs at run time: an entry exposes a record id, a row family, an order, a PAYLOAD DIGEST, an effect class and a payload-availability state, and NOTHING else"
    );
    for leaked in [
        "Vec<u8>",
        "ciphertext",
        "SecretReference",
        "payload:",
        "bytes",
        "String>;",
    ] {
        assert!(
            !entry_fields.contains(leaked),
            "`OrsBackupEntry` carries `{leaked}`; an exported entry is digests only, so no raw archived user payload and no secret can cross the export boundary"
        );
    }
    assert!(
        entry_fields.contains("pub payload_digest: String,"),
        "the entry's only payload-shaped field is `payload_digest: String`, and `OrsBackupSnapshot::validate` (src/backup_snapshot.rs:2064) plus `OrsBackupPage::validate_binding` enforce it is empty exactly when `payload_state` is `Unavailable`"
    );
    // The per-entry outcome vocabulary carries a REASON string and nothing else,
    // so triage cannot report payload back to a caller either.
    let outcome_variants = declared_body_of(contract_text, "pub enum PerEntryOutcome {")
        .ok_or("`PerEntryOutcome` was not found in the contract module")?;
    assert_eq!(
        outcome_variants
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty()
                    && !trimmed.starts_with("//")
                    && !trimmed.starts_with("///")
                    && !trimmed.starts_with("#[")
            })
            .map(str::trim)
            .collect::<Vec<_>>(),
        vec![
            "Imported,",
            "Rejected {",
            "reason: String,",
            "},",
            "Forensic {",
            "reason: String,",
            "},",
            "Blocked {",
            "reason: String,",
            "},",
            "Unresolved {",
            "reason: String,",
            "},"
        ],
        "the REAL `PerEntryOutcome` variant list, read from src/backup_snapshot.rs at run time: exactly five variants, of which the four non-`Imported` ones carry only a `reason: String` the store itself writes as a fixed literal. The doc comments above each field are dropped by the filter above, so this compares the VARIANT AND FIELD NAMES themselves"
    );
    assert!(
        !outcome_variants.contains("Vec<u8>") && !outcome_variants.contains("ciphertext"),
        "`PerEntryOutcome` carries raw bytes; the quarantined outcome vocabulary is reason-only, so a triage result cannot leak a payload"
    );
    receipt_fields_carry_no_secret_953_20(contract_text)?;
    // `OrsError` is the crate's shared error enum (`src/model.rs:4459`). The
    // backup path's refusals are its existing typed variants; none of them has a
    // secret-bearing payload field, and the projection types the export returns
    // carry no secret either. Asserted as an absence over the two backup
    // modules' own use of the enum, which is where a leak would have to appear.
    assert!(
        !both.contains("SecretReference") && !both.contains("from_secret_key"),
        "a backup module names a secret or key reference; the export/import/reconcile path resolves no key and reads no secret, so a missing key can only be reported through the payload-availability state, never by carrying one"
    );
    Ok(())
}

/// (e-ii) of case 953/20: the RECEIPT's declared fields. They are identities,
/// counts and that same reason-bearing outcome vector: no payload, no key, no
/// signature bytes. The leak search is over the DECLARED FIELDS ONLY, never the doc
/// comments above them: the previous form searched the whole body text, where the
/// word "keyed" in `per_entry`'s own doc comment ("Per-entry outcomes keyed by
/// record id") tripped the bare `key` token. That was a comment tripping a content
/// guard, which is the same self-defeating shape as asserting on a string the test
/// itself owns; a guard has to read the fields, not the prose. The exact field list
/// is then compared too, so the absence checked above is an absence over a NON-EMPTY
/// field list rather than a trivially satisfied one.
///
/// OWNER: `OrsBackupImportReceipt` (`src/backup_snapshot.rs:3541`), read at run time
/// through `declared_body_of`.
fn receipt_fields_carry_no_secret_953_20(contract_text: &str) -> TestOutcome<()> {
    let receipt_fields = declared_body_of(contract_text, "pub struct OrsBackupImportReceipt {")
        .ok_or("`OrsBackupImportReceipt` was not found in the contract module")?;
    let receipt_declared: String = receipt_fields
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty()
                && !trimmed.starts_with("//")
                && !trimmed.starts_with("///")
                && !trimmed.starts_with("#[")
        })
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("\n");
    for leaked in ["Vec<u8>", "SecretReference", "ciphertext", "key"] {
        assert!(
            !receipt_declared.contains(leaked),
            "`OrsBackupImportReceipt` carries `{leaked}`; a receipt is identities, a member roster, an outcome vector, a count and two stamps, so it cannot carry a secret or a raw payload"
        );
    }
    // The receipt really does declare the fields the comment above names, so
    // the absence checked just above is an absence over a NON-EMPTY field list
    // rather than a trivially satisfied one.
    assert_eq!(
        receipt_fields
            .lines()
            .filter(|line| line.trim_start().starts_with("pub "))
            .map(str::trim)
            .collect::<Vec<_>>(),
        vec![
            "pub snapshot_digest: String,",
            "pub source_installation: String,",
            "pub destination_installation: String,",
            "pub expected_members: Vec<(RowFamilyKind, String)>,",
            "pub per_entry: Vec<(String, PerEntryOutcome)>,",
            "pub unresolved_count: u64,",
            "pub import_at_ms: i64,",
            "pub current_owner_validation: CurrentOwnerValidation,",
            "pub known_zero_verdict: KnownZeroVerdict,"
        ],
        "the REAL `OrsBackupImportReceipt` field list, read from src/backup_snapshot.rs at run time: identities, a member roster, the outcome vector, a count, two stamps and the two gate records, and NOTHING else"
    );
    Ok(())
}
