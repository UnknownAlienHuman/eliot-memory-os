#![allow(clippy::expect_used, clippy::unwrap_used, clippy::print_stderr)]
//! Host-owned backup configuration evidence and isolated destination
//! preparation (issue #958, cases 958/1..18).
//!
//! Integration coverage over the current `main` product API in
//! `eliot_host::backup_config_projection` and
//! `eliot_host::backup_preparation`, reached through the crate (no `#[path]`
//! includes). Frozen fixtures under `tests/data/backup-preparation/`
//! (owned by the fixtures writer) are embedded with `include_str!`; machine
//! paths are substituted at runtime. Every filesystem test stages isolated
//! temp roots only (`eliot-958-<case>-<name>`); no machine-global
//! installation, credential, or user-data effects.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_host::backup_config_projection::{
    describe_audit_fence, project_backup_config, AuditFenceNote, AuthoritySnapshot,
    BackupConfigRequest, ProjectionError,
};
use eliot_host::backup_preparation::{
    cancel_preparation, cleanup_preparations, derive_destination_epoch, derive_destination_id,
    prepare_isolated_destination, reconcile_preparation, BackupCallerAuth, CleanupReport,
    DelegatedPreparation, DestinationAdmission, OwnerEvidence, PreparationClass, PreparationError,
    PreparationJournal, PreparedDestination, PresentedPreparationRequest, ReconcileDisposition,
    RootIdentity,
};
use serde_json::Value;

const LINEAGE_958: &str = "550e8400-e29b-41d4-a716-446655440000";
const HEX_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HEX_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HEX_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const HEX_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const HEX_E: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

const CONFIG_VALID_JSON: &str = include_str!("data/backup-preparation/config-request-valid.json");
const CONFIG_STALE_JSON: &str =
    include_str!("data/backup-preparation/config-request-stale-lease.json");
const ADMISSION_VALID_JSON: &str =
    include_str!("data/backup-preparation/destination-admission-valid.json");
const ADMISSION_FOREIGN_JSON: &str =
    include_str!("data/backup-preparation/destination-admission-foreign-owner.json");
const AUDIT_NOTE_JSON: &str = include_str!("data/backup-preparation/audit-fence-note.json");

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
    let raw: Value = match name {
        "destination-admission-valid.json" => {
            serde_json::from_str(ADMISSION_VALID_JSON).expect("admission shape")
        }
        "destination-admission-foreign-owner.json" => {
            serde_json::from_str(ADMISSION_FOREIGN_JSON).expect("admission shape")
        }
        other => panic!("unknown admission fixture: {other}"),
    };
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
fn projection_from_exact_owner_evidence_is_deterministic() {
    let request: BackupConfigRequest =
        serde_json::from_str(CONFIG_VALID_JSON).expect("request shape");
    let projection =
        project_backup_config(&request, &authority_from_valid(), &fence()).expect("exact projects");
    assert_eq!(projection.version, 1);
    assert_eq!(projection.installation_id, "install-958-a");
    assert_eq!(projection.owner_lease_ref, "lease-958-a-7");
    assert_eq!(projection.generation, 7);
    assert_eq!(projection.manifest_digest, HEX_A);
    assert_eq!(
        projection.build_digests,
        vec![HEX_B.to_owned(), HEX_C.to_owned()]
    );
    assert_eq!(projection.purge_ledger_revision, 3);
    assert_eq!(projection.state_fence, fence());
    assert_eq!(projection.projection_digest.len(), 64);
    // Deterministic: identical evidence re-projects to the identical digest.
    let repeat =
        project_backup_config(&request, &authority_from_valid(), &fence()).expect("re-projects");
    assert_eq!(repeat.projection_digest, projection.projection_digest);
}

// WORK_UNIT_CASE: 958/2
#[test]
fn stale_and_mixed_evidence_rejected_naming_first_field() {
    // Frozen stale fixture: stale lease ref, older generation, and a foreign
    // build digest. The projector names the first differing authority field.
    let request: BackupConfigRequest =
        serde_json::from_str(CONFIG_STALE_JSON).expect("request shape");
    assert_eq!(
        project_backup_config(&request, &authority_from_valid(), &fence())
            .expect_err("stale lease must fail"),
        ProjectionError::StaleEvidence {
            field: "owner_lease_ref"
        },
    );
    // Valid lease but an older generation: the generation field is named.
    let mut older: BackupConfigRequest =
        serde_json::from_str(CONFIG_VALID_JSON).expect("request shape");
    older.generation = 6;
    assert_eq!(
        project_backup_config(&older, &authority_from_valid(), &fence())
            .expect_err("older generation must fail"),
        ProjectionError::StaleEvidence {
            field: "generation"
        },
    );
    // Valid lease and generation but one foreign build digest: mixed evidence
    // is rejected, naming the build set.
    let mut mixed: BackupConfigRequest =
        serde_json::from_str(CONFIG_VALID_JSON).expect("request shape");
    mixed.build_digests = vec![HEX_B.to_owned(), HEX_D.to_owned()];
    assert_eq!(
        project_backup_config(&mixed, &authority_from_valid(), &fence())
            .expect_err("mixed builds must fail"),
        ProjectionError::StaleEvidence {
            field: "build_digests"
        },
    );
}

// WORK_UNIT_CASE: 958/3
#[test]
fn audit_fence_note_is_forensic_never_authority() {
    let note: AuditFenceNote = serde_json::from_str(AUDIT_NOTE_JSON).expect("note shape");
    let text = describe_audit_fence(&note);
    assert!(
        text.contains("non-authoritative"),
        "ceiling stated, got: {text}"
    );
    assert!(
        text.contains("not a lease"),
        "lease denial stated, got: {text}"
    );
    assert!(
        text.contains("current-state assertion"),
        "state denial stated, got: {text}"
    );
    // The note schema carries digests and dispositions only: no lease, grant,
    // or current-state field can ride along.
    let raw: Value = serde_json::from_str(AUDIT_NOTE_JSON).expect("note parses");
    let keys: Vec<&str> = raw
        .as_object()
        .expect("note is an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, vec!["note_digest", "observed_dispositions"]);
    // Attaching the note to an otherwise-valid request grants nothing: field
    // equality with authority evidence is still required.
    let mut request: BackupConfigRequest =
        serde_json::from_str(CONFIG_VALID_JSON).expect("request shape");
    request.audit = Some(note);
    let projection =
        project_backup_config(&request, &authority_from_valid(), &fence()).expect("still projects");
    assert_eq!(projection.owner_lease_ref, "lease-958-a-7");
}

// WORK_UNIT_CASE: 958/4
#[test]
fn secrets_excluded_by_shape_and_schema() {
    // Credential-shaped material fails digest shape; there is no secret-typed
    // field for it to land in.
    let mut request: BackupConfigRequest =
        serde_json::from_str(CONFIG_VALID_JSON).expect("request shape");
    request.manifest_digest =
        "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC".to_owned();
    assert_eq!(
        project_backup_config(&request, &authority_from_valid(), &fence())
            .expect_err("credential-shaped digest must fail"),
        ProjectionError::InvalidDigest {
            field: "manifest_digest"
        },
    );
    // Uppercase hex is not an accepted digest spelling either.
    let mut upper: BackupConfigRequest =
        serde_json::from_str(CONFIG_VALID_JSON).expect("request shape");
    upper.manifest_digest = HEX_A.to_uppercase();
    assert_eq!(
        project_backup_config(&upper, &authority_from_valid(), &fence())
            .expect_err("uppercase digest must fail"),
        ProjectionError::InvalidDigest {
            field: "manifest_digest"
        },
    );
    // The request schema is closed to the known evidence fields: no
    // password/token/secret key exists.
    let raw: Value = serde_json::from_str(CONFIG_VALID_JSON).expect("request parses");
    let mut keys: Vec<&str> = raw
        .as_object()
        .expect("request is an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "audit",
            "build_digests",
            "generation",
            "installation_id",
            "manifest_digest",
            "owner_lease_ref",
            "purge_ledger_revision",
        ],
    );
    let valid: BackupConfigRequest =
        serde_json::from_str(CONFIG_VALID_JSON).expect("request shape");
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
    if !cfg!(windows) {
        let (source_root, _) = source_tree("05");
        let parent = isolated_root("05", "staging");
        let admission =
            admission_from_fixture("destination-admission-valid.json", &source_root, &parent);
        let mut journal = MemJournal::default();
        assert_eq!(
            prepare_isolated_destination(&mut journal, &admission)
                .expect_err("non-Windows has no OS identity primitive"),
            PreparationError::PlatformUnsupported,
        );
        let _ = std::fs::remove_dir_all(&parent);
        let _ = std::fs::remove_dir_all(&source_root);
        return;
    }
    let (source_root, sentinel) = source_tree("05");
    let before = sentinel_bytes(&sentinel);
    let parent = isolated_root("05", "staging");
    let admission =
        admission_from_fixture("destination-admission-valid.json", &source_root, &parent);
    assert_eq!(admission.operation_id, "op-958-dest-05");
    assert_eq!(admission.class, PreparationClass::IsolatedRestoreRehearsal);
    let mut journal = MemJournal::default();
    let prepared = prepare_isolated_destination(&mut journal, &admission).expect("admitted");
    assert_eq!(prepared.operation_id, "op-958-dest-05");
    assert!(prepared.root.exists(), "destination created");
    let canonical_parent = std::fs::canonicalize(&parent).expect("parent canonicalizes");
    let canonical_root = std::fs::canonicalize(&prepared.root).expect("root canonicalizes");
    assert!(
        canonical_root.starts_with(&canonical_parent),
        "root under admitted parent"
    );
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
fn source_active_and_foreign_destinations_rejected() {
    if !cfg!(windows) {
        eprintln!("SKIP 958/6 on non-Windows: admission ordering needs the OS identity contour");
        return;
    }
    let (source_root, _) = source_tree("06");
    let parent = isolated_root("06", "staging");
    let mut journal = MemJournal::default();
    // Staging parent IS the source root: active installation refused.
    let active = admission("op-958-active", &source_root, &source_root);
    assert_eq!(
        prepare_isolated_destination(&mut journal, &active).expect_err("active refused"),
        PreparationError::SourceIsActive,
    );
    // Nested under the source: refused before effects.
    let nested_dir = source_root.join("nested-staging");
    std::fs::create_dir_all(&nested_dir).expect("nested dir");
    let nested = admission("op-958-nested", &source_root, &nested_dir);
    assert!(matches!(
        prepare_isolated_destination(&mut journal, &nested).expect_err("nested refused"),
        PreparationError::ArbitraryPath { .. }
    ),);
    // Preexisting foreign content at the exact destination path: refused,
    // never adopted or overwritten. The foreign-owner fixture binds the
    // takeover values (operation, nonce, foreign installation identity).
    let foreign = admission_from_fixture(
        "destination-admission-foreign-owner.json",
        &source_root,
        &parent,
    );
    assert_eq!(foreign.source_installation_id, "install-958-foreign");
    let planted = parent.join(format!(
        "dest-{}",
        derive_destination_id(&foreign.operation_id, &foreign.authority_nonce)
    ));
    std::fs::create_dir_all(&planted).expect("plant foreign dir");
    std::fs::write(planted.join("foreign-bytes.bin"), b"not-ours").expect("plant file");
    let error = prepare_isolated_destination(&mut journal, &foreign).expect_err("foreign refused");
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
fn arbitrary_path_build_profile_and_generation_rejected() {
    if !cfg!(windows) {
        eprintln!("SKIP 958/7 on non-Windows: admission ordering needs the OS identity contour");
        return;
    }
    let (source_root, _) = source_tree("07");
    let parent = isolated_root("07", "staging");
    let mut journal = MemJournal::default();
    // Missing parent.
    let missing = admission("op-958-missing", &source_root, &parent.join("no-such-dir"));
    assert!(matches!(
        prepare_isolated_destination(&mut journal, &missing).expect_err("missing refused"),
        PreparationError::ArbitraryPath { .. }
    ),);
    // File as parent.
    let file_parent = parent.join("not-a-dir");
    std::fs::write(&file_parent, b"x").expect("file");
    let fileish = admission("op-958-fileish", &source_root, &file_parent);
    assert!(matches!(
        prepare_isolated_destination(&mut journal, &fileish).expect_err("file refused"),
        PreparationError::ArbitraryPath { .. }
    ),);
    // Unapproved generation: authority disagrees with approved.
    let mut unapproved = admission("op-958-unapproved", &source_root, &parent);
    unapproved.authority_generation = 8;
    assert_eq!(
        prepare_isolated_destination(&mut journal, &unapproved).expect_err("generation refused"),
        PreparationError::UnapprovedGeneration {
            approved: 7,
            authority: 8
        },
    );
    // Zero approved generation is malformed, not merely unapproved.
    let mut zero = admission("op-958-zero-gen", &source_root, &parent);
    zero.approved_generation = 0;
    zero.authority_generation = 0;
    assert!(matches!(
        prepare_isolated_destination(&mut journal, &zero).expect_err("zero refused"),
        PreparationError::InvalidRequest { .. }
    ),);
    // Empty build identity.
    let mut empty_build = admission("op-958-empty-build", &source_root, &parent);
    empty_build.target_build = String::new();
    assert!(matches!(
        prepare_isolated_destination(&mut journal, &empty_build).expect_err("empty refused"),
        PreparationError::InvalidRequest { .. }
    ),);
    // Empty profile identity.
    let mut empty_profile = admission("op-958-empty-profile", &source_root, &parent);
    empty_profile.target_profile = String::new();
    assert!(matches!(
        prepare_isolated_destination(&mut journal, &empty_profile).expect_err("empty refused"),
        PreparationError::InvalidRequest { .. }
    ),);
    // Malformed manifest digest shape.
    let mut bad_digest = admission("op-958-bad-digest", &source_root, &parent);
    bad_digest.manifest_digest = "not-a-digest".to_owned();
    assert!(matches!(
        prepare_isolated_destination(&mut journal, &bad_digest).expect_err("digest refused"),
        PreparationError::InvalidRequest { .. }
    ),);
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/8
#[test]
fn alias_substitution_refused_and_identity_pinned() {
    use eliot_host::backup_preparation::{is_reparse_attributes, REPARSE_POINT_ATTRIBUTE};

    // The reparse-point decision bit itself is pinned on every platform: the
    // exact OS attribute refuses, anything else passes to remaining checks.
    assert!(is_reparse_attributes(REPARSE_POINT_ATTRIBUTE));
    assert_eq!(REPARSE_POINT_ATTRIBUTE, 0x400);
    assert!(!is_reparse_attributes(0x80));
    assert!(!is_reparse_attributes(0));
    if !cfg!(windows) {
        // Non-Windows has no OS identity primitive: assert the fail-closed
        // refusal directly, never a fake green.
        let (source_root, _) = source_tree("08");
        let parent = isolated_root("08", "staging");
        let mut journal = MemJournal::default();
        assert_eq!(
            prepare_isolated_destination(
                &mut journal,
                &admission("op-958-alias", &source_root, &parent)
            )
            .expect_err("non-Windows refuses before effects"),
            PreparationError::PlatformUnsupported,
        );
        let _ = std::fs::remove_dir_all(&parent);
        let _ = std::fs::remove_dir_all(&source_root);
        return;
    }
    let (source_root, _) = source_tree("08");
    let parent = isolated_root("08", "staging");
    let mut journal = MemJournal::default();
    // A symlinked staging parent is an alias substitution, refused before
    // any destination effect. Symlink creation needs privilege: when the
    // fixture link cannot be created the refusal path is reported, not
    // faked.
    let link_parent = parent.join("linked-parent");
    let real_parent = parent.join("real-parent");
    std::fs::create_dir_all(&real_parent).expect("real parent");
    match std::os::windows::fs::symlink_dir(&real_parent, &link_parent) {
        Ok(()) => {
            let aliased = admission("op-958-alias-link", &source_root, &link_parent);
            // A symlinked staging parent is refused before any destination
            // effect. The is_dir pre-gate (src:399-403) observes a symlink to
            // a directory as a non-canonical alias and refuses with
            // ArbitraryPath before the reparse check (src:404) is reached;
            // either refusal proves the alias cannot smuggle an identity.
            assert!(matches!(
                prepare_isolated_destination(&mut journal, &aliased).expect_err("alias refused"),
                PreparationError::AliasSubstitution { .. } | PreparationError::ArbitraryPath { .. }
            ),);
        }
        Err(error) => {
            eprintln!(
                "SKIP 958/8 symlink refusal: link creation withheld ({error}); pure-bit and identity checks below still run"
            );
        }
    }
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
    // Stable across repeats (idempotent), distinct across operations and
    // across nonces for the same operation.
    assert_eq!(
        first,
        derive_destination_id("op-958-fresh", "nonce-958-fresh")
    );
    assert_ne!(
        first,
        derive_destination_id("op-958-other", "nonce-958-fresh")
    );
    assert_ne!(
        first,
        derive_destination_id("op-958-fresh", "nonce-958-rotated")
    );
    let epoch = derive_destination_epoch("op-958-fresh", "nonce-958-fresh");
    assert!(epoch >= 1);
    assert_eq!(
        epoch,
        derive_destination_epoch("op-958-fresh", "nonce-958-fresh")
    );
    // Preparation-scope epochs are not caller-chosen increments: the derived
    // value ignores any archive/caller epoch presented alongside.
    assert_ne!(
        derive_destination_epoch("op-958-fresh", "nonce-958-fresh"),
        0
    );
}

// WORK_UNIT_CASE: 958/10
#[test]
fn preparation_launch_readiness_and_effect_stay_distinct() {
    let value = serde_json::to_value(admission(
        "op-958-schema",
        Path::new("C:/src"),
        Path::new("C:/staging"),
    ))
    .expect("admission serializes");
    let prepared_value = serde_json::to_value(PreparedDestination {
        operation_id: "op-958-schema".to_owned(),
        root: PathBuf::from("C:/staging/dest-x"),
        root_identity: RootIdentity {
            identity: "1:2".to_owned(),
        },
        destination_id: "d".repeat(64),
        destination_epoch: 1,
        admission_digest: "e".repeat(64),
    })
    .expect("destination serializes");
    let presented_value = serde_json::to_value(PresentedPreparationRequest {
        operation_id: "op-958-schema".to_owned(),
        class: PreparationClass::IsolatedRestoreRehearsal,
        source_installation_id: "install-958-source".to_owned(),
        staging_parent: PathBuf::from("C:/staging"),
        target_build: "build-958-approved".to_owned(),
        target_profile: "profile-958-restore".to_owned(),
        approved_generation: 7,
        authority_generation: 7,
        build_digests: vec![HEX_A.to_owned()],
        authority_nonce: "nonce-958-schema".to_owned(),
        state_fence_digest: HEX_E.to_owned(),
    })
    .expect("presented request serializes");
    for forbidden in [
        "launch",
        "readiness",
        "effect_authority",
        "activate",
        "cutover",
        "authority_grant",
    ] {
        for document in [&value, &prepared_value, &presented_value] {
            let rendered = serde_json::to_string(document).expect("render");
            assert!(
                !rendered.contains(forbidden),
                "no {forbidden} stage in preparation schema"
            );
        }
    }
    // The presented request carries build digests for subset checks, but the
    // manifest always comes from owner evidence: no caller manifest field.
    let rendered = serde_json::to_string(&presented_value).expect("render");
    assert!(
        !rendered.contains("manifest_digest"),
        "manifest is owner-bound, never presented"
    );
}

// WORK_UNIT_CASE: 958/11
#[test]
fn no_implicit_source_shutdown_or_replacement() {
    if !cfg!(windows) {
        eprintln!("SKIP 958/11 on non-Windows: preparation effects need the OS identity contour");
        return;
    }
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
    // launch/process parameters by construction (see signatures).
    assert_eq!(sentinel_bytes(&sentinel), before);
    assert_eq!(
        std::fs::metadata(&sentinel).expect("meta").len(),
        before_meta.len()
    );
    assert_eq!(
        std::fs::metadata(&sentinel)
            .expect("meta")
            .modified()
            .expect("mtime"),
        before_meta.modified().expect("mtime"),
    );
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/12
#[test]
fn exact_repeat_returns_same_destination() {
    if !cfg!(windows) {
        eprintln!("SKIP 958/12 on non-Windows: idempotency effects need the OS identity contour");
        return;
    }
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
    match reconcile_preparation(&journal, "op-958-repeat").expect("reconcile") {
        ReconcileDisposition::Current(current) => assert_eq!(current, first),
        other => panic!("expected Current, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/13
#[test]
fn changed_same_operation_input_conflicts_by_field() {
    if !cfg!(windows) {
        eprintln!("SKIP 958/13 on non-Windows: conflict detection needs the OS identity contour");
        return;
    }
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
        },
    );
    // A changed nonce is a changed input too, naming its own field.
    let mut rotated = admission("op-958-change", &source_root, &parent);
    rotated.authority_nonce = "nonce-958-rotated".to_owned();
    assert_eq!(
        prepare_isolated_destination(&mut journal, &rotated).expect_err("rotated conflicts"),
        PreparationError::ConflictField {
            field: "authority_nonce"
        },
    );
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/14
#[test]
fn lost_response_reconciles_before_retry() {
    if !cfg!(windows) {
        eprintln!("SKIP 958/14 on non-Windows: reconcile effects need the OS identity contour");
        return;
    }
    let (source_root, _) = source_tree("14");
    let parent = isolated_root("14", "staging");
    // Fresh operation with no record reconciles Absent: retry may proceed.
    let mut journal = MemJournal::default();
    assert_eq!(
        reconcile_preparation(&journal, "op-958-fresh").expect("reconcile"),
        ReconcileDisposition::Absent,
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
    ),);
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
    // Reconcile reports Uncertain (root present, unverified) - never Absent
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
    ),);
    let report =
        cleanup_preparations(&journal, &["op-958-lossy".to_owned()]).expect("cleanup runs");
    assert!(report.removed.is_empty(), "unknown never removed");
    assert_eq!(report.preserved.len(), 1);
    assert!(prepared.root.exists(), "unknown root preserved");
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/15
#[test]
fn cancellation_cleanup_preserves_source_and_unknown() {
    if !cfg!(windows) {
        eprintln!(
            "SKIP 958/15 on non-Windows: cancel/cleanup effects need the OS identity contour"
        );
        return;
    }
    let (source_root, sentinel) = source_tree("15");
    let before = sentinel_bytes(&sentinel);
    let parent = isolated_root("15", "staging");
    let mut journal = MemJournal::default();
    let prepared = prepare_isolated_destination(
        &mut journal,
        &admission("op-958-cancel", &source_root, &parent),
    )
    .expect("prepares");
    cancel_preparation(&mut journal, "op-958-cancel").expect("cancels");
    // The cancel envelope preserves the prior receipt instead of destroying
    // evidence.
    let (_, result) = journal
        .load("op-958-cancel")
        .expect("loads")
        .expect("intent present");
    let envelope = result.expect("cancel envelope present");
    assert_eq!(
        envelope.get("status").and_then(|v| v.as_str()),
        Some("cancelled")
    );
    assert!(
        envelope.get("prior_receipt").is_some(),
        "prior receipt preserved"
    );
    let report: CleanupReport =
        cleanup_preparations(&journal, &["op-958-cancel".to_owned()]).expect("cleanup runs");
    assert_eq!(report.removed, vec!["op-958-cancel".to_owned()]);
    assert!(!prepared.root.exists(), "owned root removed");
    assert_eq!(sentinel_bytes(&sentinel), before, "source preserved");
    // Cancelling the unknown is refused; Absent cannot cancel either.
    assert!(matches!(
        cancel_preparation(&mut journal, "op-958-nope"),
        Err(PreparationError::UnknownState { .. })
    ),);
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/16
#[test]
fn bounds_hold_and_rendering_stays_redacted() {
    // Oversize identity rejected at projection.
    let mut oversize_request: BackupConfigRequest =
        serde_json::from_str(CONFIG_VALID_JSON).expect("request shape");
    oversize_request.installation_id = "i".repeat(300);
    assert!(matches!(
        project_backup_config(&oversize_request, &authority_from_valid(), &fence())
            .expect_err("oversize refused"),
        ProjectionError::InvalidIdentity { .. }
    ),);
    // Control-carrying identity rejected at projection.
    let mut control_request: BackupConfigRequest =
        serde_json::from_str(CONFIG_VALID_JSON).expect("request shape");
    control_request.installation_id = "install-958-\n-a".to_owned();
    assert!(matches!(
        project_backup_config(&control_request, &authority_from_valid(), &fence())
            .expect_err("control refused"),
        ProjectionError::InvalidIdentity { .. }
    ),);
    // Oversize digest list rejected at projection.
    let mut wide: BackupConfigRequest =
        serde_json::from_str(CONFIG_VALID_JSON).expect("request shape");
    wide.build_digests = vec!["a".repeat(64); 65];
    assert!(matches!(
        project_backup_config(&wide, &authority_from_valid(), &fence()).expect_err("bound"),
        ProjectionError::BoundsExceeded { .. }
    ),);
    // Oversize identity rejected at admission (bounds shared by both ports).
    if cfg!(windows) {
        let (source_root, _) = source_tree("16");
        let parent = isolated_root("16", "staging");
        let mut journal = MemJournal::default();
        let mut oversize = admission("op-958-bounds", &source_root, &parent);
        oversize.target_build = "b".repeat(300);
        assert!(matches!(
            prepare_isolated_destination(&mut journal, &oversize).expect_err("oversize refused"),
            PreparationError::InvalidRequest { .. }
        ),);
        let _ = std::fs::remove_dir_all(&parent);
        let _ = std::fs::remove_dir_all(&source_root);
    }
    // Rendering carries truncated digests only; no 64-hex run appears.
    let temp_source = PathBuf::from("C:/src");
    let redacted = admission("op-958-redact", &temp_source, &temp_source).redacted_debug();
    assert!(!redacted.contains(HEX_A), "no full digest in rendering");
    assert!(
        !redacted.contains(HEX_E),
        "no full fence digest in rendering"
    );
    assert!(redacted.contains("op-958-redact"), "identity retained");
    assert!(redacted.contains(&HEX_A[..16]), "truncated digest present");
}

// WORK_UNIT_CASE: 958/17
#[test]
fn real_windows_isolated_root_preparation_and_cleanup() {
    if !cfg!(windows) {
        eprintln!("SKIP 958/17 on non-Windows: real isolated-root preparation requires Windows");
        return;
    }
    let (source_root, sentinel) = source_tree("17");
    let before = sentinel_bytes(&sentinel);
    let parent = isolated_root("17", "staging");
    // Registry evidence is fail-closed on a non-protected directory: owner
    // inspection refuses instead of inventing authority.
    assert!(
        matches!(
            OwnerEvidence::inspect(&parent),
            Err(PreparationError::FilesystemEffect { .. })
        ),
        "non-protected root yields no owner evidence"
    );
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
    assert_eq!(sentinel_bytes(&sentinel), before, "source unchanged");
    let report = cleanup_preparations(&journal, &["op-958-real".to_owned()]).expect("cleanup runs");
    assert_eq!(report.removed, vec!["op-958-real".to_owned()]);
    assert!(!prepared.root.exists(), "destination removed");
    assert_eq!(sentinel_bytes(&sentinel), before, "source unchanged");
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}

// WORK_UNIT_CASE: 958/18
#[test]
fn preparation_guard_excludes_registry_restore_and_cutover() {
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
    if !cfg!(windows) {
        // The closed class set and the fail-closed caller gate hold on every
        // platform, even where effects cannot run.
        match PreparationClass::IsolatedRestoreRehearsal {
            PreparationClass::IsolatedRestoreRehearsal => {}
        }
        let caller = BackupCallerAuth {
            lease_digest: HEX_A.to_owned(),
            fence_digest: HEX_E.to_owned(),
        };
        caller.check_shapes().expect("shapes hold");
        assert!(
            matches!(
                caller.authenticate(),
                Err(PreparationError::InvalidRequest { field, .. }) if field == "caller_auth"
            ),
            "unauthenticated delegation refused pending #954"
        );
        return;
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
        "source tree identical"
    );
    assert_eq!(listing(&parent).len(), 1, "exactly one destination created");
    // The delegation sink binds a journal without a second registry, store
    // recovery, archive import, or cutover stage: an empty sink reconciles
    // Absent and the caller gate stays fail-closed pending #954.
    let sink = DelegatedPreparation::new(MemJournal::default());
    assert_eq!(
        sink.reconcile("op-958-absent").expect("reconcile"),
        ReconcileDisposition::Absent,
    );
    let caller = BackupCallerAuth {
        lease_digest: HEX_A.to_owned(),
        fence_digest: HEX_E.to_owned(),
    };
    caller.check_shapes().expect("shapes hold");
    assert!(
        matches!(
            caller.authenticate(),
            Err(PreparationError::InvalidRequest { field, .. }) if field == "caller_auth"
        ),
        "unauthenticated delegation refused pending #954"
    );
    // Closed class set: exhaustive match over every variant (compile-checked;
    // adding a cutover variant breaks this test until its case exists).
    match PreparationClass::IsolatedRestoreRehearsal {
        PreparationClass::IsolatedRestoreRehearsal => {}
    }
    let _ = std::fs::remove_dir_all(&parent);
    let _ = std::fs::remove_dir_all(&source_root);
}
