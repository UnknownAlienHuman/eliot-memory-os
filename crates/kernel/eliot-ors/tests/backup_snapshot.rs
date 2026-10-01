//! Import-reconciliation completeness against an INDEPENDENT member set
//! (issue #953, A17; external audit 5868369939).
//!
//! The audit's discriminator, kept as written: a valid NONEMPTY snapshot whose
//! member `A` is still unresolved, presented with an EMPTY outcome accumulator
//! against an initialized destination whose recovery tables are empty. Before the
//! repair the producer built an empty roster from the empty accumulator, the
//! receipt carried the same empty roster, both live families were read, the
//! unresolved count was zero, and `KnownZeroVerdict::Satisfied` was reported FOR
//! `S` although `A` was never covered. The completeness check compared two
//! projections of one caller-supplied vector, so it could not observe a missing
//! import member at all.
//!
//! What is proved here, and nothing more:
//!
//! 1. [`nonempty_member_set_refuses_known_zero_for_an_untriaged_member`] — the
//!    audit's discriminator verbatim: `Satisfied` is NOT produced, because the
//!    snapshot's own declared roster says members exist.
//! 2. [`empty_member_set_still_produces_known_zero`] — the POSITIVE case: a
//!    genuinely empty, independently verified member set with an empty
//!    accumulator DOES produce `Satisfied`. This is what proves the verdict was
//!    not made unreachable by refusing everything.
//! 3. [`duplicate_outcome_identifier_is_a_typed_rejection`] — a duplicate
//!    outcome id is refused at the store boundary with
//!    `OrsError::DuplicateConflict`, a typed refusal distinguishable from both the
//!    coverage verdict and a silent collapse.
//!
//! Every fixture is a REAL temporary redb store and a REAL store-produced
//! snapshot: the archive is exported by `RedbRecoveryStore::export_backup_snapshot`
//! and re-proved by the crate's own `OrsBackupSnapshot::validate`, never
//! hand-assembled. No fake durability, no in-memory stand-in, no second database.
//! Nothing here activates authority, advances canonical ordering, or writes an
//! effect: `reconcile_backup_import` emits no store writes, and the export is a
//! read path.

use std::path::PathBuf;

use eliot_ors::{
    BACKUP_SNAPSHOT_SCHEMA_VERSION, BackupCompleteness, BackupPartialReason, EpochIdentity,
    EpochLineage, KernelAuthoritySnapshot, KnownZeroVerdict, MAX_BACKUP_BYTES,
    MAX_BACKUP_PAGE_ENTRIES, OpaqueLabel, OperationalRecordContext, OperationalRecordInput,
    OperationalRecoveryStore, OrsBackupDestination, OrsBackupFence, OrsBackupImportRequest,
    OrsBackupRequest, OrsBackupSnapshot, OrsBackupSourceIdentity, OrsError, PerEntryOutcome,
    RedbRecoveryStore, StateFenceSnapshot,
};
use eliot_platform::SecretReference;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The SOURCE installation: the store the snapshot is captured from.
const SOURCE_INSTALLATION: &str = "installation-953-w3k1-source";
/// The DESTINATION installation: the store the archive is reconciled into.
///
/// It must DIFFER from [`SOURCE_INSTALLATION`], because `validate_import_binding`
/// refuses an import whose source and destination are the same installation. Two
/// separately-bound temporary databases is how that is expressed here; neither
/// store borrows or fabricates the other's binding.
const DESTINATION_INSTALLATION: &str = "installation-953-w3k1-destination";
/// A positive Unix millisecond stamp, well past 1970 and not a sentinel.
const NOW_MS: i64 = 1_757_000_000_000;
/// 64 lowercase hex characters, the shape `require_digest` enforces for a fence.
const FENCE_DIGEST: &str = "5f1d3c9a7b2e40618da4c9f70b3e5a2c8d1f4b6e09a3c7d5e1f8b2a4c6d8e0f1";

fn database_path(case: &str) -> PathBuf {
    let nanos = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    };
    std::env::temp_dir().join(format!(
        "eliot-953-w3k1-{case}-{}-{nanos}.redb",
        std::process::id()
    ))
}

fn cleanup(path: &PathBuf) {
    let _ignored = std::fs::remove_file(path);
}

/// Opens one temporary ORS database BOUND to `installation_id`.
///
/// `RedbRecoveryStore::open` deliberately leaves the installation binding unset, and
/// every bound read then fails with "ORS database is not bound to an installed
/// identity" (`StoreObjectIdentityRecord::installed_identity`,
/// `store.rs:362`) — including `installed_store_identity`, which the export fence
/// and this fixture both need. `open_for_installation` is the entry point that binds
/// one: it writes the Host-issued identity into durable META exactly once and reads
/// the binding back, and it is what production composition uses
/// (`bins/eliot-kernel/src/composition_bootstrap.rs:597`).
///
/// The identity is a real durable binding written by the store, not a value the test
/// supplies to satisfy a check: the binding still fails closed on a later open for a
/// different installation, and the object generation is still allocated by ORS rather
/// than accepted from this test.
fn open_bound(path: &PathBuf, installation_id: &str) -> Result<RedbRecoveryStore, OrsError> {
    let (store, identity) = RedbRecoveryStore::open_for_installation(path, installation_id)?;
    // The binding is asserted, not assumed: the same readback the export fence
    // performs, so a fixture that silently failed to bind fails here with a clear
    // message instead of three confusing ones later.
    assert_eq!(
        identity.installation_id(),
        installation_id,
        "the store must report the installation it was bound to"
    );
    Ok(store)
}

fn label(value: &str) -> Result<OpaqueLabel, OrsError> {
    OpaqueLabel::new(value)
}

fn epoch(lineage: &str, value: u64) -> Result<EpochLineage, OrsError> {
    Ok(EpochLineage {
        current: EpochIdentity {
            lineage_id: label(lineage)?,
            epoch: value,
        },
        predecessor: None,
    })
}

fn fence(authority_epoch: &EpochLineage) -> Result<StateFenceSnapshot, OrsError> {
    StateFenceSnapshot::capture(
        &json!({
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

fn operational_input(
    record_id: &str,
    subject_id: &str,
    authority_epoch: EpochLineage,
    payload: &str,
) -> Result<OperationalRecordInput, OrsError> {
    let state_fence = fence(&authority_epoch)?;
    OperationalRecordInput::encrypted(
        OperationalRecordContext {
            record_id: label(record_id)?,
            subject_id: label(subject_id)?,
            authority_epoch,
            state_fence,
            created_at_ms: 100,
            cleanup_after_ms: Some(10_000),
        },
        SecretReference::new("test-key-provider", "operational-key-953-w3k1")
            .map_err(|error| OrsError::Contract(error.to_string()))?,
        payload.as_bytes().to_vec(),
    )
}

/// A committed authority snapshot: the ORS-owned row that makes this store
/// exportable at all, and the source of the fixture's ordering high-water.
///
/// Each call with a NEW `record_id` appends one further `OPERATIONAL_HISTORY`
/// row at its own operation order, so calling it twice gives the exported
/// snapshot TWO members rather than one. That matters for the duplicate case:
/// `mutate_operational` (`store.rs:30313`) treats a second record for an
/// existing subject as a lifecycle transition, admits it because the prior row
/// is `Active` and the epoch edge is equal, and persists a second history row
/// keyed by the new order — the export reads `OPERATIONAL_HISTORY`, so both rows
/// become page entries under `RowFamilyKind::OperationalHistory` with distinct
/// record ids, and `expected_member_roster` reports both.
fn commit_authority(
    store: &RedbRecoveryStore,
    record_id: &str,
) -> Result<u64, Box<dyn std::error::Error>> {
    let lineage = epoch("953-w3k1-authority-lineage", 1)?;
    let committed =
        store.commit_authority_snapshot(KernelAuthoritySnapshot::new(operational_input(
            record_id,
            "953-w3k1-authority-subject",
            lineage,
            "opaque-authority-payload-953-w3k1",
        )?)?)?;
    // The order the owner assigned is the store's observed ordering high-water,
    // which is exactly what an export request's fence must declare.
    Ok(committed.receipt().operation_order())
}

/// One exported snapshot plus the identity a reconcile request must name.
///
/// `snapshot` is produced by the store, not assembled here, and `import` binds its
/// recorded `denominator_digest` — the value `expected_import_roster` compares
/// against the archive's own original recorded digest.
struct Exported {
    snapshot: OrsBackupSnapshot,
    import: OrsBackupImportRequest,
}

/// Exports a real snapshot from `source_store` under a fence declaring `high_water`.
///
/// The three cursors are the ONLY producers of a window (the store refuses a
/// caller-minted one), and all three are attached so the snapshot declares a
/// denominator for every cursor-paged family rather than being partial evidence.
fn export_snapshot(
    source_store: &RedbRecoveryStore,
    destination_store: &RedbRecoveryStore,
    high_water: u64,
) -> Result<Exported, Box<dyn std::error::Error>> {
    // `check_export_fence` compares the declared source identity against the
    // exporting store's OWN durable binding, so the source is read back rather
    // than asserted by the test.
    let source = OrsBackupSourceIdentity::new(
        source_store
            .installed_store_identity()?
            .installation_id()
            .to_owned(),
        source_store.installed_store_identity()?.ors_generation(),
        BACKUP_SNAPSHOT_SCHEMA_VERSION,
    )?;
    let fence = OrsBackupFence::new(FENCE_DIGEST.to_owned(), high_water, NOW_MS)?;
    let request = OrsBackupRequest::new(
        source.clone(),
        fence,
        0,
        MAX_BACKUP_PAGE_ENTRIES,
        MAX_BACKUP_BYTES,
        8,
    )?
    .with_operational_cursor(source_store.open_backup_operational_history(&source, 0)?)?
    .with_process_stream_recovery_cursor(
        source_store.open_backup_process_stream_recovery_family()?,
    )?
    .with_versioned_artifact_cursor(source_store.open_backup_versioned_artifact_family()?)?;
    let snapshot = source_store.export_backup_snapshot(&request)?;
    // The reconcile destination is the RECEIVING store's own durable installation
    // binding: `reconcile_import_receipt` reads that identity back out of META and
    // refuses a request naming any other installation. It must also DIFFER from the
    // source, which `validate_import_binding` requires of a real import — hence two
    // stores rather than one.
    let destination_id = destination_store
        .installed_store_identity()?
        .installation_id()
        .to_owned();
    let import = OrsBackupImportRequest {
        snapshot_digest: snapshot.denominator_digest.clone(),
        source,
        destination: OrsBackupDestination::new(
            destination_id,
            "admission-receipt-953-w3k1".to_owned(),
            true,
        )?,
    };
    Ok(Exported { snapshot, import })
}

/// The audit's discriminator, verbatim.
///
/// A valid NONEMPTY snapshot whose member `A` is still unresolved, an EMPTY
/// outcome accumulator, and an initialized destination whose recovery tables are
/// empty. The expected result is that a known-zero verdict is REFUSED: the
/// independent denominator says members exist that nothing covered, so no number
/// of empty tables can turn that into a zero.
#[test]
fn nonempty_member_set_refuses_known_zero_for_an_untriaged_member() -> TestResult {
    let source_path = database_path("discriminator-source");
    let destination_path = database_path("discriminator-destination");
    cleanup(&source_path);
    cleanup(&destination_path);
    let source_store = open_bound(&source_path, SOURCE_INSTALLATION)?;
    let destination = open_bound(&destination_path, DESTINATION_INSTALLATION)?;
    let high_water = commit_authority(&source_store, "953-w3k1-discriminator-authority")?;

    let Exported { snapshot, import } = export_snapshot(&source_store, &destination, high_water)?;

    // Precondition, measured rather than assumed: the archive really is
    // non-empty really does declare a member, and that member really is absent
    // from the accumulator we are about to pass. Without this the test could pass
    // for the wrong reason (an empty snapshot refusing an empty accumulator is
    // not the audit's case).
    let expected = snapshot.expected_member_roster()?;
    assert!(
        !expected.is_empty(),
        "the audit's discriminator needs a NONEMPTY snapshot; this one declared no members"
    );
    assert!(
        !matches!(
            snapshot.completeness,
            BackupCompleteness::Partial {
                reason: BackupPartialReason::EmptyDenominator
            }
        ),
        "a Partial/EmptyDenominator snapshot would make the empty accumulator legitimate"
    );

    // The destination is a brand-new installation whose recovery tables are EMPTY,
    // exactly as the audit states: a new empty target has no row to collide with,
    // so every table scan below finds nothing and reports no unresolved identity.
    let receipt = destination.reconcile_backup_import(&import, &snapshot, &[], NOW_MS)?;

    assert!(
        matches!(receipt.known_zero_verdict, KnownZeroVerdict::Refused { .. }),
        "a nonempty snapshot reconciled against an EMPTY outcome accumulator must not report a known zero: {:?}",
        receipt.known_zero_verdict
    );
    // The receipt still carries the per-member outcomes the caller needs to route
    // reconciliation, and the independent roster it refused against.
    assert!(receipt.expected_members.len() == expected.len());
    assert!(receipt.per_entry.is_empty());
    assert_eq!(receipt.unresolved_count, 0);
    // The refusal is re-derivable from the recorded validation alone, not carried
    // forward from the verdict string.
    assert!(
        receipt
            .known_zero_unresolved(&receipt.current_owner_validation)
            .is_err(),
        "the recorded validation must itself refuse the known zero"
    );

    cleanup(&source_path);
    cleanup(&destination_path);
    Ok(())
}

/// The POSITIVE case: the verdict is reachable, and only for a genuinely empty,
/// independently verified member set.
///
/// This is the guard against "fixing" completeness by refusing everything. An
/// empty accumulator over an empty verified snapshot is a TRUE zero and must
/// still be reported as one.
#[test]
fn empty_member_set_still_produces_known_zero() -> TestResult {
    let source_path = database_path("positive-source");
    let destination_path = database_path("positive-destination");
    cleanup(&source_path);
    cleanup(&destination_path);
    let source_store = open_bound(&source_path, SOURCE_INSTALLATION)?;
    let destination = open_bound(&destination_path, DESTINATION_INSTALLATION)?;

    // A source store with NO operational rows at all: opening and initializing it
    // writes only META, so the ordering high-water is still zero and the
    // operational axis owes nothing. Both cursor-paged families are empty too, so
    // the snapshot's OWN completeness derivation reports the measured-empty
    // denominator — this is a measured fact, not a missing one, which is exactly
    // what keeps a genuinely empty snapshot representable.
    let high_water = 0;
    let Exported { snapshot, import } = export_snapshot(&source_store, &destination, high_water)?;

    let expected = snapshot.expected_member_roster()?;
    assert!(
        expected.is_empty(),
        "the positive case needs a genuinely EMPTY member set; this one declared {expected:?}"
    );

    let receipt = destination.reconcile_backup_import(&import, &snapshot, &[], NOW_MS)?;

    assert!(
        matches!(receipt.known_zero_verdict, KnownZeroVerdict::Satisfied),
        "an independently verified EMPTY member set with an empty accumulator is a true zero and must be reported as one: {:?}",
        receipt.known_zero_verdict
    );
    assert!(receipt.expected_members.is_empty());
    assert!(receipt.per_entry.is_empty());
    assert_eq!(receipt.unresolved_count, 0);
    assert!(
        receipt
            .known_zero_unresolved(&receipt.current_owner_validation)
            .is_ok(),
        "the recorded validation must agree with the reported verdict"
    );

    cleanup(&source_path);
    cleanup(&destination_path);
    Ok(())
}

/// A duplicate outcome identifier is a TYPED rejection, never a silent collapse.
///
/// Two outcomes for one record id are contradictory evidence about a single
/// member, not a second member, so they are refused at the store boundary with
/// `OrsError::DuplicateConflict` — a typed refusal the caller can match on, not a
/// verdict string and not a silent collapse into apparent success.
///
/// The second half proves the contrast the audit asks for: a MISSING member is a
/// different fault with a different handling. It is not a boundary error at all; it
/// is refused as a verdict on a receipt that still carries the per-member outcomes,
/// because that vector is what the caller needs to route reconciliation.
///
/// The source here commits TWO authority rows, so the archive declares TWO
/// members. That is load-bearing for the second half: with a ONE-member roster,
/// dropping the duplicated outcome leaves the roster FULLY covered and `Satisfied`
/// is the truthful verdict. A duplicate and a missing member are only
/// distinguishable when the roster is big enough for one to be missing while the
/// duplicate is still the sole fault in the other half.
#[test]
fn duplicate_outcome_identifier_is_a_typed_rejection() -> TestResult {
    let source_path = database_path("duplicate-source");
    let destination_path = database_path("duplicate-destination");
    cleanup(&source_path);
    cleanup(&destination_path);
    let source_store = open_bound(&source_path, SOURCE_INSTALLATION)?;
    let destination = open_bound(&destination_path, DESTINATION_INSTALLATION)?;
    commit_authority(&source_store, "953-w3k1-duplicate-authority-a")?;
    // The SECOND commit, so the export's frozen high-water covers both rows.
    let high_water = commit_authority(&source_store, "953-w3k1-duplicate-authority-b")?;

    let Exported { snapshot, import } = export_snapshot(&source_store, &destination, high_water)?;
    let expected = snapshot.expected_member_roster()?;
    assert!(
        expected.len() >= 2,
        "the duplicate case needs at least TWO declared members, or dropping the \
         duplicate cannot leave anything untriaged; this one declared {expected:?}"
    );
    // Two DISTINCT record ids, measured rather than assumed: the outcome
    // vocabulary is record-id keyed, so two members sharing one id would be a
    // different (and separately refused) fault than the one under test here.
    let duplicated_id = expected[0].1.clone();
    let other_id = expected[1].1.clone();
    assert_ne!(
        duplicated_id, other_id,
        "the two declared members must carry distinct record ids: {expected:?}"
    );

    // The SAME record id, twice, PLUS a complete coverage of the other member:
    // every OTHER obligation is satisfied, so the duplicate is the only fault
    // here and the typed refusal cannot be an artifact of incomplete coverage.
    let outcomes = vec![
        (duplicated_id.clone(), PerEntryOutcome::Imported),
        (other_id.clone(), PerEntryOutcome::Imported),
        (
            duplicated_id.clone(),
            PerEntryOutcome::Rejected {
                reason: "second, contradictory outcome for the same member".to_owned(),
            },
        ),
    ];
    assert_eq!(
        outcomes
            .iter()
            .filter(|(id, _)| *id == duplicated_id)
            .count(),
        2,
        "the fixture must actually present a duplicate outcome id"
    );

    // Rejection happens at the store boundary, BEFORE any current-owner
    // observation is recorded: the outcome vector is not a roster, so no
    // validation may be built from it and no receipt may be minted on it.
    assert!(
        matches!(
            destination.reconcile_backup_import(&import, &snapshot, &outcomes, NOW_MS),
            Err(OrsError::DuplicateConflict)
        ),
        "a duplicate outcome id must be refused with a TYPED error"
    );

    // And it is the DUPLICATE refusal, not the coverage one. An EMPTY outcome
    // vector leaves every member untriaged, which is INCOMPLETE COVERAGE, not a
    // contradiction: it is refused as a verdict on a receipt the caller can read
    // (so the per-member outcomes survive for routing), and never as this typed
    // error. The two faults are therefore distinguishable by RESULT type, not only
    // by variant.
    //
    // The vector must be EMPTY rather than a one-element subset. Keeping the
    // single member would leave coverage COMPLETE, so `Satisfied` would be the
    // correct verdict and this assertion would be demanding a refusal the owner
    // has no reason to give.
    let subset: Vec<(String, PerEntryOutcome)> = Vec::new();
    let incomplete = destination.reconcile_backup_import(&import, &snapshot, &subset, NOW_MS)?;
    assert!(
        matches!(
            incomplete.known_zero_verdict,
            KnownZeroVerdict::Refused { .. }
        ),
        "an untriaged member must refuse the known zero on a readable receipt: {:?}",
        incomplete.known_zero_verdict
    );
    assert_eq!(incomplete.per_entry, subset);
    assert!(matches!(
        incomplete.known_zero_unresolved(&incomplete.current_owner_validation),
        Err(OrsError::ReconciliationMismatch)
    ));

    cleanup(&source_path);
    cleanup(&destination_path);
    Ok(())
}
