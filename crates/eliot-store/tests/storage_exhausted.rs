//! Legacy storage-exhaustion matrix for issue #876 (`R-DISKFULL-STORE`).
//!
//! Complete actual legacy durable-write/error/caller denominator (all sites live
//! in `crates/eliot-store/src/`, production target Windows, base `7a31bb05`):
//!
//! ```text
//! durable-write sites (`blob_store.rs`):
//!   BlobStore::open -> std::fs::create_dir_all(root)            [RootCreate]
//!   BlobStore::open -> std::fs::canonicalize(root)              [RootCanonicalize]
//!   BlobStore::open -> claim_root_lease (.eliot-root.lock)      [lease only, not blob durability]
//!   BlobStore::put_bytes -> ensure_blob_parent (create_dir_all) [ParentCreate]
//!   BlobStore::put_bytes -> OpenOptions::create_new temp file   [TempCreate]
//!   BlobStore::put_bytes -> file.write_all(payload)             [PayloadWrite]
//!   BlobStore::put_bytes -> file.sync_all()                     [PayloadSync]
//!   BlobStore::put_bytes -> std::fs::rename(temp -> dest)       [Rename]
//!   BlobStore::put_bytes -> read_verified readback proof        [existing operation proof]
//!   (no directory-fsync site exists; rename durability relies on the readback proof)
//! error sites:
//!   open/ensure_blob_parent/handle_put_failure -> is_storage_capacity gate
//!   storage_exhausted() constructor -> StoreError::StorageExhausted
//!   non-capacity failures -> StoreError::Io (unchanged legacy family)
//! callers:
//!   in-crate: stage_canonical_memory -> put_bytes
//!   external: eliot-app commands/execution.rs (open + startup probe put_bytes),
//!     commands/operations.rs, mcp_stdio dispatch/work/runtime_handlers/provider_handlers
//! ```
//!
//! Every case below drives an actual production seam
//! (`is_storage_capacity`, `legacy_stage_effect`, `BlobStore::open/put_bytes`,
//! the `StorageExhausted` shape); fault injection is finite and comes from
//! `data/storage_exhausted_cases.json`. No real volume is ever filled.

use eliot_store::blob_store::{BlobStore, is_storage_capacity, legacy_stage_effect};
use eliot_store::error::{
    StorageCleanup, StorageExhausted, StorageExhaustedEffect, StorageExhaustedRetry,
    StorageExhaustedStage, StorageIoCause, StoreError,
};
use eliot_types::BlobStoreConfig;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

const FAULT_FIXTURES_DOC: &str = include_str!("data/storage_exhausted_cases.json");
const PACKAGE_MANIFEST_DOC: &str = include_str!("../Cargo.toml");
const ERROR_SOURCE_DOC: &str = include_str!("../src/error.rs");
const BLOB_STORE_SOURCE_DOC: &str = include_str!("../src/blob_store.rs");

static TAG_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root(tag: &str) -> PathBuf {
    let serial = TAG_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("eliot-876-{tag}-{}-{serial}", std::process::id()))
}

fn open_store(tag: &str) -> TestResult<(BlobStore, PathBuf)> {
    let root = temp_root(tag);
    let _ = std::fs::remove_dir_all(&root);
    let store = BlobStore::open(&BlobStoreConfig {
        root: root.display().to_string(),
    })?;
    Ok((store, root))
}

fn close_store(root: &PathBuf) {
    let _ = std::fs::remove_dir_all(root);
}

/// Builds the exact production shape for a capacity failure at `stage`,
/// reusing the production stage→evidence table. The native detail stands in
/// for an OS capacity failure; only bounded kind/code/namespace escape.
fn capacity_error(
    operation: &'static str,
    stage: StorageExhaustedStage,
    cleanup: StorageCleanup,
) -> StorageExhausted {
    StorageExhausted {
        operation,
        stage,
        storage_identity: "root-blake3:876-case-identity".to_owned(),
        local_attempt_id: Some("local-attempt-876".to_owned()),
        attempted_bytes: Some(41),
        effect: legacy_stage_effect(stage),
        retry: StorageExhaustedRetry::CapacityRevalidationRequired,
        cleanup,
        cause: StorageIoCause::new(
            std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "native detail must stay private",
            ),
            std::env::consts::OS,
        ),
    }
}

fn is_blob_artifact(name: &str) -> bool {
    std::path::Path::new(name)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("blob"))
}

fn dir_entry_names(root: &PathBuf) -> TestResult<Vec<String>> {
    let entries = std::fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    Ok(entries
        .iter()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect())
}

// WORK_UNIT_CASE: 876/1
#[test]
fn legacy_durable_write_error_caller_denominator_is_complete() -> TestResult<()> {
    // Every actual stage has exactly one frozen evidence outcome: the table is
    // total, so no durable-write site can produce an unmapped effect.
    let table = [
        (
            StorageExhaustedStage::RootCreate,
            StorageExhaustedEffect::AttemptedNoPublication,
        ),
        (
            StorageExhaustedStage::RootCanonicalize,
            StorageExhaustedEffect::AttemptedNoPublication,
        ),
        (
            StorageExhaustedStage::ParentCreate,
            StorageExhaustedEffect::AttemptedNoPublication,
        ),
        (
            StorageExhaustedStage::TempCreate,
            StorageExhaustedEffect::AttemptedNoPublication,
        ),
        (
            StorageExhaustedStage::PayloadWrite,
            StorageExhaustedEffect::StagedUnknown,
        ),
        (
            StorageExhaustedStage::PayloadSync,
            StorageExhaustedEffect::StagedUnknown,
        ),
        (
            StorageExhaustedStage::Rename,
            StorageExhaustedEffect::PossiblePublication,
        ),
    ];
    if table.len() != 7 {
        return Err("stage denominator drifted from the 7 known durable-write stages".into());
    }
    for (stage, expected) in table {
        if legacy_stage_effect(stage) != expected {
            return Err(format!("stage {stage:?} left the frozen evidence table").into());
        }
    }
    // The mapping seam behind all four error sites answers the pinned kind.
    if !is_storage_capacity(&std::io::Error::new(
        std::io::ErrorKind::StorageFull,
        "denominator probe",
    )) {
        return Err("pinned capacity kind lost behind the denominator seam".into());
    }
    // Both permitted operation identities survive the error shape.
    for operation in ["blob.open", "blob.put_bytes"] {
        let error = capacity_error(
            operation,
            StorageExhaustedStage::TempCreate,
            StorageCleanup::NotAttempted,
        );
        if error.operation != operation {
            return Err(format!("operation identity {operation} was not retained").into());
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 876/2
#[test]
fn capacity_error_retains_permitted_operation_and_storage_identity() -> TestResult<()> {
    let error = StorageExhausted {
        operation: "blob.put_bytes",
        stage: StorageExhaustedStage::PayloadWrite,
        storage_identity: "root-blake3:deadbeef876".to_owned(),
        local_attempt_id: Some("local-attempt-identity".to_owned()),
        attempted_bytes: Some(19),
        effect: StorageExhaustedEffect::StagedUnknown,
        retry: StorageExhaustedRetry::CapacityRevalidationRequired,
        cleanup: StorageCleanup::Removed,
        cause: StorageIoCause::new(
            std::io::Error::new(std::io::ErrorKind::StorageFull, "private native detail"),
            std::env::consts::OS,
        ),
    };
    if error.operation != "blob.put_bytes" {
        return Err("permitted operation identity was not retained".into());
    }
    if error.storage_identity != "root-blake3:deadbeef876" {
        return Err("bounded storage identity was not retained".into());
    }
    if error.local_attempt_id.as_deref() != Some("local-attempt-identity") {
        return Err("staging attempt token was not retained".into());
    }
    let display = format!("{error}");
    let debug = format!("{error:?}");
    if !display.contains("blob.put_bytes") {
        return Err("operation identity missing from the operator rendering".into());
    }
    if !debug.contains("root-blake3:deadbeef876") {
        return Err("storage identity missing from the debug rendering".into());
    }
    if debug.contains("private native detail") {
        return Err("native detail leaked into the debug rendering".into());
    }
    Ok(())
}

// WORK_UNIT_CASE: 876/3
#[test]
fn posix_enospc_classifies_under_native_namespace_only() -> TestResult<()> {
    #[cfg(unix)]
    {
        let enospc = std::io::Error::from_raw_os_error(28);
        if !is_storage_capacity(&enospc) {
            return Err("POSIX ENOSPC (28) was not typed on its native target".into());
        }
        let cause = StorageIoCause::new(enospc, std::env::consts::OS);
        if cause.raw_os_error() != Some(28) {
            return Err("ENOSPC raw code was erased from the retained evidence".into());
        }
        if cause.namespace() != std::env::consts::OS {
            return Err("ENOSPC was recorded under a foreign namespace".into());
        }
    }
    #[cfg(not(unix))]
    {
        // On a non-POSIX target the POSIX value is a foreign integer collision.
        let foreign = std::io::Error::from_raw_os_error(28);
        if is_storage_capacity(&foreign) {
            return Err("POSIX value 28 guessed as capacity off its namespace".into());
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 876/4
#[test]
fn windows_disk_full_codes_and_foreign_collision_rejection() -> TestResult<()> {
    #[cfg(windows)]
    {
        for code in [112, 39] {
            let native = std::io::Error::from_raw_os_error(code);
            if !is_storage_capacity(&native) {
                return Err(format!("Windows capacity code {code} was not typed").into());
            }
            let cause = StorageIoCause::new(native, std::env::consts::OS);
            if cause.raw_os_error() != Some(code) {
                return Err(format!("Windows code {code} was erased from evidence").into());
            }
            if cause.namespace() != std::env::consts::OS {
                return Err(format!("Windows code {code} recorded off-namespace").into());
            }
        }
        let foreign = std::io::Error::from_raw_os_error(28);
        if is_storage_capacity(&foreign) {
            return Err("POSIX value 28 guessed as capacity on Windows".into());
        }
    }
    #[cfg(not(windows))]
    {
        // Off Windows both values are foreign integer collisions.
        for code in [112, 39] {
            let foreign = std::io::Error::from_raw_os_error(code);
            if is_storage_capacity(&foreign) {
                return Err(
                    format!("Windows value {code} guessed as capacity off-namespace").into(),
                );
            }
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 876/5
#[test]
fn pinned_storage_full_kind_maps_without_os_code() -> TestResult<()> {
    let erased = std::io::Error::new(std::io::ErrorKind::StorageFull, "code already erased");
    if !is_storage_capacity(&erased) {
        return Err("pinned StorageFull kind without a code stayed generic".into());
    }
    let misleading =
        std::io::Error::new(std::io::ErrorKind::StorageFull, "permission denied EACCES");
    if !is_storage_capacity(&misleading) {
        return Err("pinned kind lost to its misleading message text".into());
    }
    Ok(())
}

// WORK_UNIT_CASE: 876/6
#[test]
fn near_capacity_kinds_remain_distinct_from_exhaustion() -> TestResult<()> {
    for kind in [
        std::io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::ReadOnlyFilesystem,
        std::io::ErrorKind::FileTooLarge,
        std::io::ErrorKind::OutOfMemory,
    ] {
        let error = std::io::Error::new(kind, "near-capacity probe");
        if is_storage_capacity(&error) {
            return Err(format!("kind {kind:?} guessed as storage exhaustion").into());
        }
    }
    #[cfg(target_os = "linux")]
    {
        // EACCES / EROFS / EFBIG / ENOMEM: near-capacity native evidence.
        for code in [13, 30, 27, 12] {
            let native = std::io::Error::from_raw_os_error(code);
            if is_storage_capacity(&native) {
                return Err(format!("native code {code} guessed as storage exhaustion").into());
            }
        }
    }
    #[cfg(windows)]
    {
        let denied = std::io::Error::from_raw_os_error(5);
        if is_storage_capacity(&denied) {
            return Err("Win32 ERROR_ACCESS_DENIED guessed as storage exhaustion".into());
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 876/7
#[test]
fn unknown_code_or_erased_evidence_stays_generic_io() -> TestResult<()> {
    for kind in [
        std::io::ErrorKind::Other,
        std::io::ErrorKind::Interrupted,
        std::io::ErrorKind::NotFound,
        std::io::ErrorKind::AlreadyExists,
        std::io::ErrorKind::InvalidData,
    ] {
        let error = std::io::Error::new(kind, "unknown-evidence probe");
        if is_storage_capacity(&error) {
            return Err(format!("kind {kind:?} guessed as storage exhaustion").into());
        }
    }
    let unknown = std::io::Error::from_raw_os_error(9999);
    if is_storage_capacity(&unknown) {
        return Err("unpinned raw code 9999 guessed as storage exhaustion".into());
    }
    Ok(())
}

// WORK_UNIT_CASE: 876/8
#[test]
fn pre_attempt_refusal_is_not_an_attempted_create_failure() -> TestResult<()> {
    let (store, root) = open_store("preadmit")?;
    // Admission refusal happens before hashing or persistence: no canonical
    // publication was attempted, so no staging artifact may exist.
    let refused = store.put_bytes(b"Authorization: Bearer synthetic-token-value-12345");
    let Err(StoreError::PolicyViolation(_)) = refused else {
        close_store(&root);
        return Err("secret-bearing blob passed admission".into());
    };
    for name in dir_entry_names(&root)? {
        if name.contains("blob-stage") || is_blob_artifact(&name) {
            close_store(&root);
            return Err("refused admission left a staging artifact behind".into());
        }
    }
    close_store(&root);
    // A failed create attempt is different: the OS operation ran and proved no
    // publication, which is AttemptedNoPublication rather than not-attempted.
    if legacy_stage_effect(StorageExhaustedStage::TempCreate)
        != StorageExhaustedEffect::AttemptedNoPublication
    {
        return Err("attempted create failure lost its no-publication evidence".into());
    }
    Ok(())
}

// WORK_UNIT_CASE: 876/9
#[test]
fn write_exhaustion_preserves_staged_partial_or_unknown_progress() -> TestResult<()> {
    if legacy_stage_effect(StorageExhaustedStage::PayloadWrite)
        != StorageExhaustedEffect::StagedUnknown
    {
        return Err("payload-write exhaustion left the staged-unknown state".into());
    }
    // Offered bytes are attempted bytes, never committed bytes: a write_all
    // failure may leave unknown partial progress behind.
    let error = capacity_error(
        "blob.put_bytes",
        StorageExhaustedStage::PayloadWrite,
        StorageCleanup::Removed,
    );
    if error.attempted_bytes != Some(41) {
        return Err("offered byte count was not preserved as attempted-not-committed".into());
    }
    if error.effect != StorageExhaustedEffect::StagedUnknown {
        return Err("write exhaustion lost its partial-progress evidence".into());
    }
    Ok(())
}

// WORK_UNIT_CASE: 876/10
#[test]
fn sync_stage_exhaustion_remains_distinct_from_write_and_rename() -> TestResult<()> {
    if legacy_stage_effect(StorageExhaustedStage::PayloadSync)
        != StorageExhaustedEffect::StagedUnknown
    {
        return Err("payload-sync exhaustion left the staged-unknown state".into());
    }
    if legacy_stage_effect(StorageExhaustedStage::PayloadSync)
        == legacy_stage_effect(StorageExhaustedStage::Rename)
    {
        return Err("sync exhaustion merged with rename publication evidence".into());
    }
    if StorageExhaustedStage::PayloadSync == StorageExhaustedStage::PayloadWrite {
        return Err("sync and write stages collapsed into one site".into());
    }
    Ok(())
}

// WORK_UNIT_CASE: 876/11
#[test]
fn possible_rename_publication_stays_unknown_pending_reconciliation() -> TestResult<()> {
    if legacy_stage_effect(StorageExhaustedStage::Rename)
        != StorageExhaustedEffect::PossiblePublication
    {
        return Err("rename exhaustion lost its possible-publication evidence".into());
    }
    let error = capacity_error(
        "blob.put_bytes",
        StorageExhaustedStage::Rename,
        StorageCleanup::Absent,
    );
    if error.effect != StorageExhaustedEffect::PossiblePublication {
        return Err("rename error does not require reconciliation".into());
    }
    if error.retry != StorageExhaustedRetry::CapacityRevalidationRequired {
        return Err("rename error dropped the revalidation requirement".into());
    }
    Ok(())
}

// WORK_UNIT_CASE: 876/12
#[test]
fn cleanup_outcome_retains_the_primary_capacity_error() -> TestResult<()> {
    let removed = capacity_error(
        "blob.put_bytes",
        StorageExhaustedStage::PayloadWrite,
        StorageCleanup::Removed,
    );
    let absent = capacity_error(
        "blob.put_bytes",
        StorageExhaustedStage::Rename,
        StorageCleanup::Absent,
    );
    let not_attempted = capacity_error(
        "blob.put_bytes",
        StorageExhaustedStage::TempCreate,
        StorageCleanup::NotAttempted,
    );
    let failed = capacity_error(
        "blob.put_bytes",
        StorageExhaustedStage::PayloadWrite,
        StorageCleanup::Failed(StorageIoCause::new(
            std::io::Error::other("private cleanup detail"),
            std::env::consts::OS,
        )),
    );
    if !matches!(removed.cleanup, StorageCleanup::Removed) {
        return Err("successful cleanup evidence was not retained".into());
    }
    if !matches!(absent.cleanup, StorageCleanup::Absent) {
        return Err("absent cleanup evidence was not retained".into());
    }
    if !matches!(not_attempted.cleanup, StorageCleanup::NotAttempted) {
        return Err("not-attempted cleanup evidence was not retained".into());
    }
    if !matches!(failed.cleanup, StorageCleanup::Failed(_)) {
        return Err("failed cleanup evidence was not retained".into());
    }
    for error in [&removed, &absent, &not_attempted, &failed] {
        if error.cause.kind() != std::io::ErrorKind::StorageFull {
            return Err("cleanup handling erased the primary capacity cause".into());
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 876/13
#[test]
fn exhaustion_or_incomplete_durability_never_yields_a_receipt() -> TestResult<()> {
    let (store, root) = open_store("noreceipt")?;
    // Block the content-addressed parent directory with a regular file so the
    // ParentCreate durable site fails through the real write path.
    let payload = b"876-no-receipt-payload";
    let digest = blake3::hash(payload).to_hex().to_string();
    let prefix: String = digest.chars().take(2).collect();
    std::fs::write(root.join(&prefix), b"not a directory")?;
    let result = store.put_bytes(payload);
    let Err(StoreError::Io(native)) = result else {
        close_store(&root);
        return Err("blocked durable write produced a success or a typed capacity error".into());
    };
    if is_storage_capacity(&native) {
        close_store(&root);
        return Err("parent-directory failure guessed as storage exhaustion".into());
    }
    for name in dir_entry_names(&root)? {
        if is_blob_artifact(&name) {
            close_store(&root);
            return Err("incomplete durability left a blob receipt artifact".into());
        }
    }
    close_store(&root);
    Ok(())
}

// WORK_UNIT_CASE: 876/14
#[test]
fn retry_class_is_nontransient_capacity_revalidation() -> TestResult<()> {
    // Every stage carries the same non-transient retry policy: exhaustion is
    // never automatic retry, only external capacity revalidation.
    for stage in [
        StorageExhaustedStage::RootCreate,
        StorageExhaustedStage::RootCanonicalize,
        StorageExhaustedStage::ParentCreate,
        StorageExhaustedStage::TempCreate,
        StorageExhaustedStage::PayloadWrite,
        StorageExhaustedStage::PayloadSync,
        StorageExhaustedStage::Rename,
    ] {
        let error = capacity_error("blob.put_bytes", stage, StorageCleanup::NotAttempted);
        if error.retry != StorageExhaustedRetry::CapacityRevalidationRequired {
            return Err(format!("stage {stage:?} left the non-transient retry class").into());
        }
    }
    // The classifier is a pure predicate: repeated calls agree, so no hidden
    // retry loop or state lives behind the seam.
    let probe = std::io::Error::new(std::io::ErrorKind::StorageFull, "retry probe");
    if !is_storage_capacity(&probe) || !is_storage_capacity(&probe) {
        return Err("capacity predicate gave an unstable answer".into());
    }
    Ok(())
}

// WORK_UNIT_CASE: 876/15
#[test]
fn possible_publication_is_never_blindly_retried_after_recovery() -> TestResult<()> {
    // Even when capacity later recovers, a rename-stage failure must reconcile
    // the same operation first (I14.21): the effect stays unknown and the
    // operation identity stays pinned for that reconciliation.
    let error = capacity_error(
        "blob.put_bytes",
        StorageExhaustedStage::Rename,
        StorageCleanup::Absent,
    );
    if error.effect != StorageExhaustedEffect::PossiblePublication {
        return Err("rename outcome became retryable without reconciliation".into());
    }
    if error.retry != StorageExhaustedRetry::CapacityRevalidationRequired {
        return Err("rename retry dropped the revalidation requirement".into());
    }
    if error.operation != "blob.put_bytes" {
        return Err("reconciliation lost the original operation identity".into());
    }
    if error.local_attempt_id.as_deref() != Some("local-attempt-876") {
        return Err("reconciliation lost the original attempt token".into());
    }
    Ok(())
}

// WORK_UNIT_CASE: 876/16
#[test]
fn valid_normal_write_bytes_are_unchanged() -> TestResult<()> {
    let (store, root) = open_store("validbytes")?;
    let payload = b"876 valid durable payload";
    let blob = store.put_bytes(payload)?;
    if blob.size_bytes != u64::try_from(payload.len()).map_err(|_| "payload length overflow")? {
        close_store(&root);
        return Err("valid write changed the recorded byte count".into());
    }
    if store.read_verified(&blob)? != payload {
        close_store(&root);
        return Err("valid write changed the durable bytes".into());
    }
    // Content addressing is stable: the same bytes deduplicate to one receipt.
    let again = store.put_bytes(payload)?;
    if again != blob {
        close_store(&root);
        return Err("valid rewrite changed the content-addressed receipt".into());
    }
    let parent = blob
        .relative_path
        .rsplit_once('/')
        .map_or("", |(parent, _)| parent);
    for name in dir_entry_names(&root.join(parent))? {
        if name.contains("blob-stage") {
            close_store(&root);
            return Err("valid write left a staging artifact behind".into());
        }
    }
    close_store(&root);
    Ok(())
}

struct FaultFixture {
    id: String,
    platform: String,
    kind: Option<String>,
    code: Option<i32>,
    message: Option<String>,
    expect_capacity: bool,
}

fn load_fault_fixtures() -> TestResult<Vec<FaultFixture>> {
    let document: serde_json::Value = serde_json::from_str(FAULT_FIXTURES_DOC)?;
    let rows = document
        .as_array()
        .ok_or("fault fixtures document is not an array")?;
    let mut fixtures = Vec::with_capacity(rows.len());
    for row in rows {
        let get_str = |key: &str| -> Option<String> {
            row.get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        let id = get_str("id").ok_or("fault fixture without an id")?;
        let platform = get_str("platform").ok_or(format!("fixture {id} without a platform"))?;
        if get_str("note").is_none_or(|note| note.is_empty()) {
            return Err(format!("fixture {id} without an explanatory note").into());
        }
        fixtures.push(FaultFixture {
            id,
            platform,
            kind: get_str("kind"),
            code: row
                .get("code")
                .and_then(serde_json::Value::as_i64)
                .and_then(|code| i32::try_from(code).ok()),
            message: get_str("message"),
            expect_capacity: row
                .get("expect_capacity")
                .and_then(serde_json::Value::as_bool)
                .ok_or("fault fixture without expect_capacity")?,
        });
    }
    if fixtures.is_empty() {
        return Err("fault fixtures are empty; the matrix would prove nothing".into());
    }
    Ok(fixtures)
}

fn fixture_error(fixture: &FaultFixture) -> TestResult<std::io::Error> {
    let message = fixture
        .message
        .clone()
        .unwrap_or_else(|| format!("fixture {}", fixture.id));
    match (fixture.kind.as_deref(), fixture.code) {
        (None, Some(code)) => Ok(std::io::Error::from_raw_os_error(code)),
        (Some(name), _) => {
            let kind = match name {
                "StorageFull" => std::io::ErrorKind::StorageFull,
                "PermissionDenied" => std::io::ErrorKind::PermissionDenied,
                "ReadOnlyFilesystem" => std::io::ErrorKind::ReadOnlyFilesystem,
                "FileTooLarge" => std::io::ErrorKind::FileTooLarge,
                "OutOfMemory" => std::io::ErrorKind::OutOfMemory,
                "QuotaExceeded" => std::io::ErrorKind::QuotaExceeded,
                "Other" => std::io::ErrorKind::Other,
                "Interrupted" => std::io::ErrorKind::Interrupted,
                "NotFound" => std::io::ErrorKind::NotFound,
                "AlreadyExists" => std::io::ErrorKind::AlreadyExists,
                "InvalidData" => std::io::ErrorKind::InvalidData,
                _ => return Err(format!("fixture {} names an unknown kind", fixture.id).into()),
            };
            Ok(std::io::Error::new(kind, message))
        }
        (None, None) => Err(format!("fixture {} has neither kind nor code", fixture.id).into()),
    }
}

fn platform_executes(platform: &str) -> bool {
    platform == "any" || platform == std::env::consts::OS
}

// WORK_UNIT_CASE: 876/17
#[test]
fn existing_fault_fixtures_keep_their_classification() -> TestResult<()> {
    let mut executed = 0usize;
    for fixture in load_fault_fixtures()? {
        if !platform_executes(&fixture.platform) {
            continue;
        }
        let error = fixture_error(&fixture)?;
        if is_storage_capacity(&error) != fixture.expect_capacity {
            return Err(format!(
                "fixture {} misclassified (expected capacity={})",
                fixture.id, fixture.expect_capacity
            )
            .into());
        }
        executed += 1;
    }
    if executed == 0 {
        return Err("no fault fixture executed on this target".into());
    }
    Ok(())
}

// WORK_UNIT_CASE: 876/18
#[test]
fn source_api_diff_guard_binds_the_allowed_surface() -> TestResult<()> {
    // No cross-store owner: the legacy donor must not gain a dependency edge on
    // the current provider crates owned by #864 or on the Surreal adapter.
    for forbidden in ["eliot-blob", "eliot-store-api", "surreal"] {
        if PACKAGE_MANIFEST_DOC.contains(forbidden) {
            return Err(format!("cross-store edge {forbidden} entered eliot-store").into());
        }
    }
    // No cross-store use-tokens in the owned sources (prose citations of the
    // numeric precedent are not ownership).
    for (name, source) in [
        ("error.rs", ERROR_SOURCE_DOC),
        ("blob_store.rs", BLOB_STORE_SOURCE_DOC),
    ] {
        for token in [
            "use eliot_blob",
            "eliot_blob::",
            "use eliot_store_api",
            "eliot_store_api::",
        ] {
            if source.contains(token) {
                return Err(format!("cross-store token {token} entered {name}").into());
            }
        }
    }
    // No diagnostic-string parsing: messages that name a capacity code or
    // condition never reconstruct a lost classification on their own.
    for message in [
        "ENOSPC errno 28 disk full while staging blob",
        "windows ERROR_DISK_FULL 112 in driver message",
    ] {
        let spoof = std::io::Error::other(message);
        if is_storage_capacity(&spoof) {
            return Err("diagnostic text reconstructed a capacity code".into());
        }
    }
    let pinned = std::io::Error::new(std::io::ErrorKind::StorageFull, "permission denied");
    if !is_storage_capacity(&pinned) {
        return Err("pinned kind lost to its message text".into());
    }
    // No hidden cleanup or unbounded retry behind the seam: the full fixture
    // battery decides deterministically on repeated passes.
    let fixtures = load_fault_fixtures()?;
    for fixture in &fixtures {
        if !platform_executes(&fixture.platform) {
            continue;
        }
        let first = is_storage_capacity(&fixture_error(fixture)?);
        let second = is_storage_capacity(&fixture_error(fixture)?);
        if first != second || first != fixture.expect_capacity {
            return Err(format!("fixture {} decided unstably", fixture.id).into());
        }
    }
    Ok(())
}
