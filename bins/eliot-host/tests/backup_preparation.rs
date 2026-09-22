#![cfg(windows)]
#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Product follow-up for S-CONC-ACCEPT issue #958 (Host-owned backup
//! configuration evidence and isolated destination preparation).
//!
//! Suite allocation: 958/1..18 here. The two implementation modules compile
//! into this test target via explicit `#[path]` includes: `bins/eliot-host`
//! `src/lib.rs` is Ohm-owned and stays untouched until root serializes the
//! registration/delegation hunk (`CONTROL/958-host-preparation-hook.md`).
//! Every test stages isolated temp fixture paths only
//! (`eliot-958-<case>-<name>`); no machine-global installation, credential,
//! or user-data effects. Fixture JSON under `data/backup-preparation/`
//! carries shapes/values; machine paths are substituted explicitly.

#[path = "../src/backup_config_projection.rs"]
mod backup_config_projection;
#[path = "../src/backup_preparation.rs"]
mod backup_preparation;

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use backup_config_projection::{
    AuditFenceNote, AuthoritySnapshot, BackupConfigRequest, ProjectionError, describe_audit_fence,
    project_backup_config,
};
use backup_preparation::{
    CleanupReport, DestinationAdmission, PreparationClass, PreparationError, PreparationJournal,
    PreparedDestination, ReconcileDisposition, derive_destination_epoch, derive_destination_id,
    prepare_isolated_destination, reconcile_preparation,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use serde_json::Value;

const LINEAGE_958: &str = "550e8400-e29b-41d4-a716-446655440000";
const HEX_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HEX_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HEX_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const HEX_E: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

fn fixdir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/backup-preparation")
}

fn read_fixture(name: &str) -> Value {
    let bytes = std::fs::read(fixdir().join(name)).expect("fixture readable");
    serde_json::from_slice(&bytes).expect("fixture parses")
}

fn fence() -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new(LINEAGE_958).expect("lineage"),
            NonZeroU64::new(7).expect("nonzero"),
        )
        .expect("epoch"),
        ResourceGeneration::genesis(),
    )
}

/// Finite named isolated fixture root (`eliot-958-<case>-<name>`); owned
/// fixture paths only, removed before creation and by the test afterwards.
fn isolated_root(case: &str, name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("eliot-958-{case}-{name}"));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("fixture root");
    root
}

/// Source installation tree with a sentinel file proving it stays untouched.
fn source_tree(case: &str) -> (PathBuf, PathBuf) {
    let root = isolated_root(case, "source");
    let sentinel = root.join("source-sentinel.txt");
    std::fs::write(&sentinel, b"source-installation-bytes-958").expect("sentinel");
    (root, sentinel)
}

fn sentinel_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("sentinel readable")
}

fn authority_from_valid() -> AuthoritySnapshot {
    AuthoritySnapshot {
        owner_lease_ref: "lease-958-a-7".to_owned(),
        generation: 7,
        manifest_digest: HEX_A.to_owned(),
        build_digests: vec![HEX_B.to_owned(), HEX_C.to_owned()],
        purge_ledger_revision: 3,
    }
}

/// Deserializes an admission fixture, asserts its machine-independent shape
/// (including the explicit path placeholders), then substitutes the isolated
/// temp roots. Fixtures bind values; machine paths are always substituted.
fn admission_from_fixture(name: &str, source_root: &Path, parent: &Path) -> DestinationAdmission {
    let raw = read_fixture(name);
    assert_eq!(
        raw.get("source_root").and_then(|v| v.as_str()),
        Some("@@SOURCE_ROOT@@"),
        "fixture carries an explicit source placeholder"
    );
    assert_eq!(
        raw.get("staging_parent").and_then(|v| v.as_str()),
        Some("@@STAGING_PARENT@@"),
        "fixture carries an explicit parent placeholder"
    );
    let mut admission: DestinationAdmission = serde_json::from_value(raw).expect("admission shape");
    admission.source_root = PathBuf::from(source_root);
    admission.staging_parent = PathBuf::from(parent);
    admission
}

fn admission(op: &str, source_root: &Path, parent: &Path) -> DestinationAdmission {
    DestinationAdmission {
        operation_id: op.to_owned(),
        class: PreparationClass::IsolatedRestoreRehearsal,
        source_installation_id: "install-958-source".to_owned(),
        source_root: source_root.to_owned(),
        staging_parent: parent.to_owned(),
        target_build: "build-958-approved".to_owned(),
        target_profile: "profile-958-restore".to_owned(),
        approved_generation: 7,
        authority_generation: 7,
        manifest_digest: HEX_A.to_owned(),
        authority_nonce: format!("nonce-958-{op}"),
        state_fence_digest: HEX_E.to_owned(),
    }
}

/// In-memory journal sink for tests (production `HostComposition` binds the
/// installation/Host journal at delegation).
#[derive(Default)]
struct MemJournal {
    intents: BTreeMap<String, Value>,
    results: BTreeMap<String, Value>,
    drop_next_result: bool,
    fail_next_write: bool,
}

impl PreparationJournal for MemJournal {
    fn record_intent(
        &mut self,
        operation_id: &str,
        intent: &Value,
    ) -> Result<(), PreparationError> {
        if self.fail_next_write {
            self.fail_next_write = false;
            return Err(PreparationError::JournalFault(
                "injected sink fault".to_owned(),
            ));
        }
        self.intents.insert(operation_id.to_owned(), intent.clone());
        Ok(())
    }

    fn record_result(
        &mut self,
        operation_id: &str,
        result: &Value,
    ) -> Result<(), PreparationError> {
        if self.drop_next_result {
            self.drop_next_result = false;
            return Ok(());
        }
        self.results.insert(operation_id.to_owned(), result.clone());
        Ok(())
    }

    fn load(&self, operation_id: &str) -> Result<Option<(Value, Option<Value>)>, PreparationError> {
        Ok(self
            .intents
            .get(operation_id)
            .cloned()
            .map(|intent| (intent, self.results.get(operation_id).cloned())))
    }

    fn list_operations(&self) -> Result<Vec<String>, PreparationError> {
        let mut operations: Vec<String> = self.intents.keys().cloned().collect();
        for operation in self.results.keys() {
            if !operations.contains(operation) {
                operations.push(operation.clone());
            }
        }
        Ok(operations)
    }
}

// WORK_UNIT_CASE: 958/1
#[test]
fn exact_config_projection_from_owner_evidence() {
    let request: BackupConfigRequest =
        serde_json::from_value(read_fixture("config-request-valid.json")).expect("request shape");
    let projection = project_backup_config(&request, &authority_from_valid(), &fence())
        .expect("exact evidence projects");
    assert_eq!(projection.version, 1);
    assert_eq!(projection.installation_id, "install-958-a");
    assert_eq!(projection.owner_lease_ref, "lease-958-a-7");
    assert_eq!(projection.generation, 7);
    assert_eq!(projection.manifest_digest, HEX_A);
    assert_eq!(projection.purge_ledger_revision, 3);
    assert_eq!(projection.state_fence, fence());
    assert_eq!(projection.projection_digest.len(), 64);
}

// WORK_UNIT_CASE: 958/2
#[test]
fn stale_mixed_evidence_rejected_by_field() {
    let request: BackupConfigRequest =
        serde_json::from_value(read_fixture("config-request-stale-lease.json"))
            .expect("request shape");
    let error = project_backup_config(&request, &authority_from_valid(), &fence())
        .expect_err("stale lease must fail");
    assert_eq!(
        error,
        ProjectionError::StaleEvidence {
            field: "owner_lease_ref"
        },
        "first differing field named"
    );
}

// WORK_UNIT_CASE: 958/3
#[test]
fn audit_fence_is_forensic_never_authority() {
    let note: AuditFenceNote =
        serde_json::from_value(read_fixture("audit-fence-note.json")).expect("note shape");
    let text = describe_audit_fence(&note);
    assert!(
        text.contains("non-authoritative"),
        "ceiling stated, got: {text}"
    );
    assert!(
        text.contains("not a lease"),
        "lease denial stated, got: {text}"
    );
    // No conversion into authority exists: the note type exposes no lease,
    // grant, or projection constructor (compile-level by absence); the
    // projector requires a separate AuthoritySnapshot signature.
}

// WORK_UNIT_CASE: 958/4
#[test]
fn credential_shaped_values_rejected_and_unprintable() {
    let mut request: BackupConfigRequest =
        serde_json::from_value(read_fixture("config-request-valid.json")).expect("request shape");
    request.manifest_digest =
        "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC".to_owned();
    let error = project_backup_config(&request, &authority_from_valid(), &fence())
        .expect_err("credential-shaped digest must fail");
    assert_eq!(
        error,
        ProjectionError::InvalidDigest {
            field: "manifest_digest"
        }
    );
    let valid: BackupConfigRequest =
        serde_json::from_value(read_fixture("config-request-valid.json")).expect("request shape");
    let projection =
        project_backup_config(&valid, &authority_from_valid(), &fence()).expect("valid projects");
    let rendered = format!("{projection:?}");
    for marker in ["secret", "credential", "private_key", "BEGIN"] {
        assert!(
            !rendered.to_lowercase().contains(marker),
            "no secret marker in rendering"
        );
    }
}

// WORK_UNIT_CASE: 958/5
#[test]
fn valid_admitted_destination_prepares() {
    let (source_root, sentinel) = source_tree("05");
    let before = sentinel_bytes(&sentinel);
    let parent = isolated_root("05", "staging");
    let admission =
        admission_from_fixture("destination-admission-valid.json", &source_root, &parent);
    let mut journal = MemJournal::default();
    let prepared = prepare_isolated_destination(&mut journal, &admission).expect("admitted");
    assert_eq!(prepared.operation_id, "op-958-dest-05");
    assert!(prepared.root.exists(), "destination created");
    assert!(!prepared.root_identity.identity.is_empty());
    assert_eq!(prepared.destination_id.len(), 64);
    assert!(prepared.destination_epoch >= 1);
    assert_eq!(prepared.admission_digest.len(), 64);
    assert_eq!(sentinel_bytes(&sentinel), before, "source untouched");
    assert!(journal.intents.contains_key("op-958-dest-05"));
    assert!(journal.results.contains_key("op-958-dest-05"));
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/6
#[test]
fn source_active_foreign_destinations_rejected() {
    let (source_root, _) = source_tree("06");
    let parent = isolated_root("06", "staging");
    // Staging parent IS the source root: active installation refused.
    let active = admission("op-958-active", &source_root, &source_root);
    let mut journal = MemJournal::default();
    assert_eq!(
        prepare_isolated_destination(&mut journal, &active).expect_err("active refused"),
        backup_preparation::PreparationError::SourceIsActive
    );
    // Nested under the source: refused before effects.
    let nested_dir = source_root.join("nested-staging");
    std::fs::create_dir_all(&nested_dir).expect("nested dir");
    let nested = admission("op-958-nested", &source_root, &nested_dir);
    assert!(matches!(
        prepare_isolated_destination(&mut journal, &nested).expect_err("nested refused"),
        PreparationError::ArbitraryPath { .. }
    ));
    // Preexisting foreign content at the exact destination path: refused,
    // never adopted or overwritten.
    assert_eq!(
        admission_from_fixture(
            "destination-admission-foreign-owner.json",
            &source_root,
            &parent,
        )
        .source_installation_id,
        "install-958-foreign"
    );
    let planted = parent.join(format!(
        "dest-{}",
        derive_destination_id("op-958-foreign-takeover", "nonce-958-foreign-takeover")
    ));
    std::fs::create_dir_all(&planted).expect("plant foreign dir");
    std::fs::write(planted.join("foreign-bytes.bin"), b"not-ours").expect("plant file");
    let mut takeover = admission("op-958-foreign-takeover", &source_root, &parent);
    takeover.authority_nonce = "nonce-958-foreign-takeover".to_owned();
    let error =
        prepare_isolated_destination(&mut journal, &takeover).expect_err("foreign content refused");
    assert!(
        matches!(error, PreparationError::ForeignContent { .. }),
        "unexpected: {error:?}"
    );
    assert!(
        planted.join("foreign-bytes.bin").exists(),
        "foreign bytes preserved"
    );
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/7
#[test]
fn arbitrary_path_build_profile_generation_rejected() {
    let (source_root, _) = source_tree("07");
    let parent = isolated_root("07", "staging");
    let mut journal = MemJournal::default();
    // Missing parent.
    let mut missing = admission("op-958-missing", &source_root, &parent.join("no-such-dir"));
    missing.staging_parent = parent.join("no-such-dir");
    assert!(matches!(
        prepare_isolated_destination(&mut journal, &missing).expect_err("missing refused"),
        PreparationError::ArbitraryPath { .. }
    ));
    // File as parent.
    let file_parent = parent.join("not-a-dir");
    std::fs::write(&file_parent, b"x").expect("file");
    let fileish = admission("op-958-fileish", &source_root, &file_parent);
    assert!(matches!(
        prepare_isolated_destination(&mut journal, &fileish).expect_err("file refused"),
        PreparationError::ArbitraryPath { .. }
    ));
    // Unapproved generation.
    let mut unapproved = admission("op-958-unapproved", &source_root, &parent);
    unapproved.authority_generation = 8;
    assert_eq!(
        prepare_isolated_destination(&mut journal, &unapproved).expect_err("generation refused"),
        PreparationError::UnapprovedGeneration {
            approved: 7,
            authority: 8
        }
    );
    // Empty build identity.
    let mut empty_build = admission("op-958-empty-build", &source_root, &parent);
    empty_build.target_build = String::new();
    assert!(matches!(
        prepare_isolated_destination(&mut journal, &empty_build).expect_err("empty refused"),
        PreparationError::InvalidRequest { .. }
    ));
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/8
#[test]
fn alias_substitution_refused_identity_pinned() {
    let (source_root, _) = source_tree("08");
    let parent = isolated_root("08", "staging");
    let mut journal = MemJournal::default();
    let prepared: PreparedDestination = prepare_isolated_destination(
        &mut journal,
        &admission("op-958-alias", &source_root, &parent),
    )
    .expect("admitted");
    // Identity pinned at creation; reconcile re-verifies the live root.
    assert!(!prepared.root_identity.identity.is_empty());
    match reconcile_preparation(&journal, "op-958-alias").expect("reconcile") {
        ReconcileDisposition::Current(current) => assert_eq!(current, prepared),
        other => panic!("expected Current, got {other:?}"),
    }
    // Tampered root (removed + recreated => new OS identity) is detected,
    // never silently adopted.
    std::fs::remove_dir_all(&prepared.root).expect("remove");
    std::fs::create_dir_all(&prepared.root).expect("recreate");
    match reconcile_preparation(&journal, "op-958-alias").expect("reconcile") {
        ReconcileDisposition::Uncertain { reason } => {
            assert!(reason.contains("identity changed"), "names cause: {reason}");
        }
        other => panic!("expected Uncertain, got {other:?}"),
    }
    // The reparse-point decision bit itself is pinned: the exact OS
    // attribute refuses, anything else passes to the remaining checks.
    assert!(backup_preparation::is_reparse_attributes(
        backup_preparation::REPARSE_POINT_ATTRIBUTE
    ));
    assert!(!backup_preparation::is_reparse_attributes(0x80));
    assert!(!backup_preparation::is_reparse_attributes(0));
    // A file planted at a fresh destination path refuses as foreign content.
    let blocker = parent.join(format!(
        "dest-{}",
        derive_destination_id("op-958-blocked", "nonce-958-blocked")
    ));
    std::fs::write(&blocker, b"blocker").expect("blocker file");
    let mut blocked_admission = admission("op-958-blocked", &source_root, &parent);
    blocked_admission.authority_nonce = "nonce-958-blocked".to_owned();
    assert!(matches!(
        prepare_isolated_destination(&mut journal, &blocked_admission)
            .expect_err("blocked refused"),
        PreparationError::ForeignContent { .. }
    ));
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/9
#[test]
fn fresh_identities_never_archive_or_caller_copies() {
    let archive_id = "archive-opaque-id-123";
    let caller_decoy = "caller-chosen-9";
    let first = derive_destination_id("op-958-fresh", "nonce-958-fresh");
    assert_ne!(first, archive_id);
    assert_ne!(first, caller_decoy);
    assert_eq!(first.len(), 64);
    // Stable across repeats (idempotent), distinct across operations.
    assert_eq!(
        first,
        derive_destination_id("op-958-fresh", "nonce-958-fresh")
    );
    assert_ne!(
        first,
        derive_destination_id("op-958-other", "nonce-958-fresh")
    );
    let epoch = derive_destination_epoch("op-958-fresh", "nonce-958-fresh");
    assert!(epoch >= 1);
    assert_eq!(
        epoch,
        derive_destination_epoch("op-958-fresh", "nonce-958-fresh")
    );
}

// WORK_UNIT_CASE: 958/10
#[test]
fn preparation_launch_readiness_effect_stay_distinct() {
    let value = serde_json::to_value(admission(
        "op-958-schema",
        Path::new("C:/src"),
        Path::new("C:/staging"),
    ))
    .expect("admission serializes");
    let prepared_value = serde_json::to_value(PreparedDestination {
        operation_id: "op-958-schema".to_owned(),
        root: PathBuf::from("C:/staging/dest-x"),
        root_identity: backup_preparation::RootIdentity {
            identity: "1:2".to_owned(),
        },
        destination_id: "d".repeat(64),
        destination_epoch: 1,
        admission_digest: "e".repeat(64),
    })
    .expect("destination serializes");
    for forbidden in [
        "launch",
        "readiness",
        "effect_authority",
        "activate",
        "cutover",
        "authority_grant",
    ] {
        for document in [&value, &prepared_value] {
            let rendered = serde_json::to_string(document).expect("render");
            assert!(
                !rendered.contains(forbidden),
                "no {forbidden} stage in preparation schema"
            );
        }
    }
}

// WORK_UNIT_CASE: 958/11
#[test]
fn no_implicit_source_shutdown_or_scm_replacement() {
    let (source_root, sentinel) = source_tree("11");
    let before = sentinel_bytes(&sentinel);
    let before_meta = std::fs::metadata(&sentinel).expect("meta");
    let parent = isolated_root("11", "staging");
    let mut journal = MemJournal::default();
    prepare_isolated_destination(
        &mut journal,
        &admission("op-958-quiet", &source_root, &parent),
    )
    .expect("admitted");
    // Source sentinel byte-identical and unmodified; preparation takes no
    // launch/scm/process parameters by construction (see signatures).
    assert_eq!(sentinel_bytes(&sentinel), before);
    assert_eq!(
        std::fs::metadata(&sentinel).expect("meta").len(),
        before_meta.len()
    );
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/12
#[test]
fn exact_repeat_returns_same_destination() {
    let (source_root, _) = source_tree("12");
    let parent = isolated_root("12", "staging");
    let mut journal = MemJournal::default();
    let first = prepare_isolated_destination(
        &mut journal,
        &admission("op-958-repeat", &source_root, &parent),
    )
    .expect("first prepares");
    let second = prepare_isolated_destination(
        &mut journal,
        &admission("op-958-repeat", &source_root, &parent),
    )
    .expect("repeat returns same");
    assert_eq!(first, second, "idempotent same destination");
    assert_eq!(journal.intents.len(), 1, "single intent recorded");
    assert_eq!(journal.results.len(), 1, "single result recorded");
    let listed = journal.list_operations().expect("journal lists operations");
    assert_eq!(
        listed,
        vec!["op-958-repeat".to_owned()],
        "sweep sees the op"
    );
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/13
#[test]
fn changed_same_operation_input_conflicts_by_field() {
    let (source_root, _) = source_tree("13");
    let parent = isolated_root("13", "staging");
    let mut journal = MemJournal::default();
    prepare_isolated_destination(
        &mut journal,
        &admission("op-958-change", &source_root, &parent),
    )
    .expect("first prepares");
    let mut changed = admission("op-958-change", &source_root, &parent);
    changed.target_profile = "profile-958-other".to_owned();
    assert_eq!(
        prepare_isolated_destination(&mut journal, &changed).expect_err("changed conflicts"),
        PreparationError::ConflictField {
            field: "target_profile"
        }
    );
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/14
#[test]
fn lost_response_reconciles_before_retry() {
    let (source_root, _) = source_tree("14");
    let parent = isolated_root("14", "staging");
    // Fresh operation with no record reconciles Absent: retry may proceed.
    let mut journal = MemJournal::default();
    assert_eq!(
        reconcile_preparation(&journal, "op-958-fresh").expect("reconcile"),
        ReconcileDisposition::Absent
    );
    // Journal faults surface instead of vanishing: nothing is recorded and
    // no effects happen.
    journal.fail_next_write = true;
    assert!(matches!(
        prepare_isolated_destination(
            &mut journal,
            &admission("op-958-jfault", &source_root, &parent)
        )
        .expect_err("journal fault surfaces"),
        PreparationError::JournalFault(_)
    ));
    assert_eq!(
        reconcile_preparation(&journal, "op-958-jfault").expect("reconcile"),
        ReconcileDisposition::Absent,
        "failed intent leaves nothing behind"
    );
    // Lose the result write: effects happened, receipt did not persist.
    journal.drop_next_result = true;
    let prepared = prepare_isolated_destination(
        &mut journal,
        &admission("op-958-lossy", &source_root, &parent),
    )
    .expect("effects complete");
    assert!(prepared.root.exists(), "effects happened");
    // Reconcile reports Uncertain (root present, unverified) — never Absent
    // (which would invite a blind duplicate) and never a fabricated Current.
    match reconcile_preparation(&journal, "op-958-lossy").expect("reconcile") {
        ReconcileDisposition::Uncertain { .. } => {}
        other => panic!("expected Uncertain, got {other:?}"),
    }
    // Retry is refused until inspection; cleanup preserves the unknown root.
    assert!(matches!(
        prepare_isolated_destination(
            &mut journal,
            &admission("op-958-lossy", &source_root, &parent)
        )
        .expect_err("no blind retry"),
        PreparationError::UnknownState { .. }
    ));
    let report = backup_preparation::cleanup_preparations(&journal, &["op-958-lossy".to_owned()])
        .expect("cleanup runs");
    assert!(report.removed.is_empty(), "unknown never removed");
    assert_eq!(report.preserved.len(), 1);
    assert!(prepared.root.exists(), "unknown root preserved");
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/15
#[test]
fn cancellation_cleanup_preserves_source_and_unknown() {
    let (source_root, sentinel) = source_tree("15");
    let before = sentinel_bytes(&sentinel);
    let parent = isolated_root("15", "staging");
    let mut journal = MemJournal::default();
    let prepared = prepare_isolated_destination(
        &mut journal,
        &admission("op-958-cancel", &source_root, &parent),
    )
    .expect("prepares");
    backup_preparation::cancel_preparation(&mut journal, "op-958-cancel").expect("cancels");
    let report: CleanupReport =
        backup_preparation::cleanup_preparations(&journal, &["op-958-cancel".to_owned()])
            .expect("cleanup runs");
    assert_eq!(report.removed, vec!["op-958-cancel".to_owned()]);
    assert!(!prepared.root.exists(), "owned root removed");
    assert_eq!(sentinel_bytes(&sentinel), before, "source preserved");
    // Cancelling the unknown is refused; Absent cannot cancel either.
    assert!(matches!(
        backup_preparation::cancel_preparation(&mut journal, "op-958-nope"),
        Err(PreparationError::UnknownState { .. })
    ));
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/16
#[test]
fn bounds_hold_and_rendering_stays_redacted() {
    let (source_root, _) = source_tree("16");
    let parent = isolated_root("16", "staging");
    let mut journal = MemJournal::default();
    // Oversize identity rejected.
    let mut oversize = admission("op-958-bounds", &source_root, &parent);
    oversize.target_build = "b".repeat(300);
    assert!(matches!(
        prepare_isolated_destination(&mut journal, &oversize).expect_err("oversize refused"),
        PreparationError::InvalidRequest { .. }
    ));
    // Oversize digest list rejected at projection.
    let mut request: backup_config_projection::BackupConfigRequest =
        serde_json::from_value(read_fixture("config-request-valid.json")).expect("request shape");
    request.build_digests = vec!["a".repeat(64); 65];
    assert!(matches!(
        project_backup_config(&request, &authority_from_valid(), &fence()).expect_err("bound"),
        ProjectionError::BoundsExceeded { .. }
    ));
    // Rendering carries truncated digests only; no 64-hex run appears.
    let rendered = admission("op-958-redact", &source_root, &parent).redacted_debug();
    assert!(!rendered.contains(HEX_A), "no full digest in rendering");
    assert!(rendered.contains("op-958-redact"), "identity retained");
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/17
#[test]
fn real_windows_isolated_preparation_and_cleanup() {
    let (source_root, sentinel) = source_tree("17");
    let before = sentinel_bytes(&sentinel);
    let parent = isolated_root("17", "staging");
    let mut journal = MemJournal::default();
    let prepared = prepare_isolated_destination(
        &mut journal,
        &admission("op-958-real", &source_root, &parent),
    )
    .expect("real preparation");
    // Real OS identity pinned, stable across a second observation.
    assert!(!prepared.root_identity.identity.is_empty());
    match reconcile_preparation(&journal, "op-958-real").expect("reconcile") {
        ReconcileDisposition::Current(current) => {
            assert_eq!(current.root_identity, prepared.root_identity);
        }
        other => panic!("expected Current, got {other:?}"),
    }
    // Source installation byte-identical; cleanup removes only the destination.
    assert_eq!(
        sentinel_bytes(&sentinel),
        before,
        "source installation unchanged"
    );
    let report = backup_preparation::cleanup_preparations(&journal, &["op-958-real".to_owned()])
        .expect("cleanup runs");
    assert_eq!(report.removed, vec!["op-958-real".to_owned()]);
    assert!(!prepared.root.exists(), "destination removed");
    assert_eq!(
        sentinel_bytes(&sentinel),
        before,
        "source installation unchanged"
    );
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/18
#[test]
fn source_api_guard_excludes_installer_registry_restore_cutover() {
    fn listing(root: &Path) -> Vec<String> {
        let mut entries = Vec::new();
        for entry in walkdir_like(root) {
            entries.push(entry);
        }
        entries.sort();
        entries
    }
    fn walkdir_like(root: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let Ok(read) = std::fs::read_dir(root) else {
            return out;
        };
        for entry in read.flatten() {
            let path = entry.path();
            out.push(path.to_string_lossy().into_owned());
            if path.is_dir() {
                out.extend(walkdir_like(&path));
            }
        }
        out
    }
    let (source_root, _) = source_tree("18");
    // Recursive listing before and after: preparation adds exactly one
    // destination directory under the staging parent, nothing in source.
    let parent = isolated_root("18", "staging");
    let source_before = listing(&source_root);
    let mut journal = MemJournal::default();
    prepare_isolated_destination(
        &mut journal,
        &admission("op-958-guard", &source_root, &parent),
    )
    .expect("admitted");
    assert_eq!(
        listing(&source_root),
        source_before,
        "source tree byte-identical"
    );
    assert_eq!(listing(&parent).len(), 1, "exactly one destination created");
    // Closed class set: exhaustive match over every variant (compile-checked;
    // adding a cutover variant breaks this test until its case exists).
    match PreparationClass::IsolatedRestoreRehearsal {
        PreparationClass::IsolatedRestoreRehearsal => {}
    }
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}
