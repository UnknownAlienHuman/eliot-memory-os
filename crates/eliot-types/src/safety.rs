use crate::MemoryPressureReport;
use crate::ids::ProjectId;
use crate::memory::{PathRef, TaintClass, WriteReceiptRef};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataRootProfile {
    pub profile_id: String,
    pub mode: DataRootMode,
    pub root: PathRef,
    pub store_root: PathRef,
    pub blob_root: PathRef,
    pub backup_root: PathRef,
    pub export_root: PathRef,
    pub import_root: PathRef,
    pub report_root: PathRef,
    pub log_root: PathRef,
    pub spool_root: PathRef,
    pub worktree_root: PathRef,
    pub incident_root: PathRef,
    pub config_root: PathRef,
    pub policy_root: PathRef,
    pub tmp_root: PathRef,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataRootMode {
    DevProjectLocal,
    ProductionLocal,
    RecoveryOffline,
    TestIsolated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataRootValidation {
    pub profile_id: String,
    pub root: PathRef,
    pub status: DataRootValidationStatus,
    pub checks: Vec<DataRootCheck>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataRootValidationStatus {
    Valid,
    ValidWithWarnings,
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataRootCheck {
    pub name: String,
    pub status: DataRootCheckStatus,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataRootCheckStatus {
    Pass,
    Warning,
    Error,
}

/// Decode-time pin for `BackupManifest::schema_version` (#938, cases 7-8):
/// a misselected version must not become valid current input. The only
/// supported value is the crate's own adopted `crate::SCHEMA_VERSION`
/// (the sole writer emits exactly it); anything else refuses.
fn deserialize_manifest_schema_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value != crate::SCHEMA_VERSION {
        return Err(serde::de::Error::custom(format!(
            "unsupported backup manifest schema_version: {value:?}"
        )));
    }
    Ok(value)
}

/// Module-local required-nullable decoder used by rows `sd1`..`sd7` of issue
/// #938. This is the crate's ESTABLISHED CONVENTION, not a workaround: three
/// byte-identical private copies of this exact function already exist -
/// `crates/eliot-types/src/provider_invocation.rs:7-13`,
/// `crates/eliot-types/src/memory.rs:221-227` and
/// `crates/eliot-types/src/cognition.rs:401-407` - and
/// `crates/eliot-types/src/lib.rs:3-39` exposes no shared serde-helper module for
/// them to come from. A private item cannot be imported across modules, and
/// `lib.rs` is closed to this issue, so `safety.rs` keeps its own single
/// definition, the same way it already keeps its own
/// `deserialize_manifest_schema_version` above. A reader weighing a fourth copy
/// should know three already exist by convention.
///
/// Plain removal of `#[serde(default)]` would NOT refuse: `serde_derive` reaches
/// `missing_field`, whose `MissingFieldDeserializer` answers `deserialize_option`
/// with `visit_none()`, so an absent `Option<T>` is `None` either way. This
/// function is the refusing form: used with no `default` beside it, serde must
/// find the key, while an explicit `null` still decodes to `None` — the
/// `APPENDIX-P:12` rule that `authority, scope, effect, privacy, ordering and
/// receipt fields are never silently defaulted;` together with the `I05-16:46`
/// rule that `Fields that do not apply remain explicit `None`; they are not
/// silently omitted from the semantic model.`
fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    pub backup_id: String,
    pub created_at: OffsetDateTime,
    pub source_data_root: PathRef,
    pub backup_root: PathRef,
    pub backup_kind: BackupKind,
    pub governor_version: String,
    #[serde(deserialize_with = "deserialize_manifest_schema_version")]
    pub schema_version: String,
    pub policy_snapshot_refs: Vec<String>,
    pub config_snapshot_refs: Vec<String>,
    pub surreal_export_ref: Option<String>,
    pub surreal_export_status: String,
    /// `sd1`. Effect-bearing current form: the canonical key is now REQUIRED on
    /// the way in, so an omitted `surreal_source_endpoint` refuses instead of
    /// decoding as `None`. Safe for current bytes because the only producer
    /// writes the key unconditionally — `crates/eliot-engine/src/safety/backup.rs::BackupService::build_backup:145`
    /// (`config.map(|config| config.endpoint.clone())`, no `skip_serializing_if`
    /// path) — and `Option<T>` already serializes `None` as `null`; readers are
    /// `BackupService::read_manifest:284`, `BackupService::verify:192` and
    /// `crates/eliot-engine/src/safety.rs::RestoreService::run_logical:556`.
    /// Judged individually: the omission is not neutral here, because
    /// `run_logical:556` computes `endpoint_isolated` as
    /// `manifest.surreal_source_endpoint.as_deref() != Some(target_config.endpoint.as_str())`,
    /// so a silently defaulted `None` makes the backup source and the restore
    /// target look different and satisfies the isolation boundary for free —
    /// against `APPENDIX-P:12` (`authority, scope, effect, privacy, ordering and
    /// receipt fields are never silently defaulted;`), `A13-07:16` (`Cutover
    /// requires separate authority.`) and the `I05-16:46` explicit-`None` rule.
    /// No versioned compatibility owner is accepted: `BackupManifest.schema_version`
    /// is pinned by `deserialize_manifest_schema_version` to `crate::SCHEMA_VERSION`,
    /// so no enclosing version selects a legacy interpretation of the omission
    /// (`I05-22:4`, `core schema is explicit and versioned;`).
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub surreal_source_endpoint: Option<String>,
    /// `sd2`. Effect-bearing current form: the canonical key is now REQUIRED and an
    /// omitted `surreal_source_storage_ref` refuses. The only producer writes the key
    /// unconditionally — `crates/eliot-engine/src/safety/backup.rs::BackupService::build_backup:146-148`
    /// (`config.and_then(|config| config.storage_root.as_ref()).map(path_ref)`), so
    /// every current manifest already carries `null` or a path; the reader is
    /// `crates/eliot-engine/src/safety.rs::RestoreService::run_logical:557-566`.
    /// Judged individually: `run_logical` reads it as
    /// `.as_deref().is_none_or(|source| ... !same_path(Path::new(source), target))`,
    /// so an omitted key decodes to the permissive `None` branch and the storage
    /// half of the isolated-target boundary passes without ever having been stated —
    /// against `APPENDIX-P:12`, `A13-07:16` and `I05-16:46`. No versioned
    /// compatibility owner is accepted: the enclosing `schema_version` pin admits no
    /// historical form (`I05-22:4`).
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub surreal_source_storage_ref: Option<PathRef>,
    pub control_wal_snapshot_ref: Option<String>,
    pub blob_manifest_ref: String,
    /// `sd3`. Effect-bearing current form: the canonical key is now REQUIRED and an
    /// omitted `blob_payload_root` refuses. The only producer writes the key
    /// unconditionally — `crates/eliot-engine/src/safety/backup.rs::BackupService::build_backup:152`
    /// (the value itself is computed at `:77-83` and is `None` only for a dry run),
    /// so every current manifest already carries `null` or a path; the reader is
    /// `crates/eliot-engine/src/safety/backup.rs::verify_blob_payload_manifest:386`,
    /// which reads `manifest.blob_payload_root` at `:390-394`.
    /// Judged individually: this is the locator of the copied blob payloads on a
    /// recovery manifest, so it is a receipt-class binding under `APPENDIX-P:12`
    /// (`authority, scope, effect, privacy, ordering and receipt fields are never
    /// silently defaulted;`), and the enclosing `schema_version` pin admits no
    /// historical form that could read an omission as intent (`I05-22:4`). The
    /// downstream reader already fails closed for a completed manifest
    /// (`:394`, `completed backup has no blob payload root`), which is exactly why
    /// an omission carries no accepted legacy meaning and has no versioned
    /// compatibility owner: the `I05-13:44` rule that `Missing blobs, an
    /// unexplained revision gap or an incoherent ORS fence fails that class rather
    /// than producing a partial "successful" backup` must not be reachable by
    /// silently dropping the locator. An explicit `null` stays legal — that is what
    /// a dry-run manifest emits, per the `I05-16:46` explicit-`None` rule.
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub blob_payload_root: Option<PathRef>,
    pub blob_payloads: Vec<BackupBlobEntry>,
    pub report_manifest_ref: Option<String>,
    pub checksums: Vec<BackupChecksum>,
    pub copied_live_db_files: bool,
    pub dry_run: bool,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupBlobEntry {
    pub relative_path: PathRef,
    pub backup_path: PathRef,
    pub checksum: BackupChecksum,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupInventoryEntry {
    pub backup_id: String,
    pub created_at: OffsetDateTime,
    pub status: BackupStatus,
    pub manifest_ref: PathRef,
    pub verified: bool,
    pub age_seconds: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupKind {
    LogicalExport,
    OfflineSnapshot,
    IncrementalLogical,
    PreMigration,
    TestFixture,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupChecksum {
    pub algorithm: String,
    pub path: PathRef,
    pub digest_hex: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupReceipt {
    pub backup_id: String,
    pub status: BackupStatus,
    pub manifest_ref: String,
    pub bytes_written: u64,
    pub objects_written: u64,
    pub started_at: OffsetDateTime,
    pub finished_at: OffsetDateTime,
    pub errors: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupStatus {
    Succeeded,
    SucceededWithWarnings,
    Failed,
    Partial,
    DryRunOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupReport {
    pub component: String,
    pub manifest: BackupManifest,
    pub receipt: BackupReceipt,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorePlan {
    pub restore_plan_id: String,
    pub backup_id: String,
    pub backup_manifest_ref: String,
    pub target_data_root: PathRef,
    pub restore_mode: RestoreMode,
    /// `sd4`. Effect-bearing current form: the canonical key is now REQUIRED and an
    /// omitted `target_endpoint` refuses. All three producers write the key
    /// unconditionally — `crates/eliot-engine/src/safety.rs::RestoreService::plan_from_manifest:789`
    /// (the struct literal always emits `target_endpoint: None`), then
    /// `RestoreService::run_logical:573` and `RestoreService::plan_logical:705`
    /// overwrite it with the real endpoint; the plan travels in the persisted
    /// `restore-evidence/restore-receipt.json` written at `:679-683`.
    /// Judged individually: `RestorePlan` carries NO version field at all, so no
    /// enclosing wire version could select a documented interpretation of the
    /// omission, and none is invented here (`I05-22:4`, `core schema is explicit
    /// and versioned;`). The endpoint is the half of the restore target identity
    /// that `A13-07:16` (`Cutover requires separate authority.`) and the `I05-13`
    /// restore procedure depend on, so per `APPENDIX-P:12` it is an effect field
    /// that is never silently defaulted; the `I05-16:46` explicit-`None` rule is
    /// preserved because the key may still be present and `null`. No versioned
    /// compatibility owner and no lower proof ceiling are recorded because no
    /// historical form is accepted.
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub target_endpoint: Option<String>,
    /// `sd5`. Effect-bearing current form: the canonical key is now REQUIRED and an
    /// omitted `target_storage_ref` refuses. Producers always write the key —
    /// `crates/eliot-engine/src/safety.rs::RestoreService::plan_from_manifest:790`,
    /// then `RestoreService::run_logical:574` and `RestoreService::plan_logical:706`.
    /// Judged individually and for a different reason than `sd4`: this is a
    /// filesystem locator for the restore target, and `RestoreService::run_logical:557-566`
    /// proves source/target storage isolation FROM the manifest's counterpart while
    /// `plan_from_manifest` always plans `None` here — so a defaulted omission is a
    /// path claim that was never made, against `APPENDIX-P:12` and the `A13-07:16`
    /// `Cutover requires separate authority.` rule. `RestorePlan` has no version
    /// field, so no legacy interpretation is selectable (`I05-22:4`); no
    /// compatibility owner is invented. `I05-16:46` keeps explicit `null` legal.
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub target_storage_ref: Option<PathRef>,
    /// `sd6`. Effect-bearing current form: the canonical key is now REQUIRED and an
    /// omitted `exact_action_hash` refuses. Producers always write the key —
    /// `crates/eliot-engine/src/safety.rs::RestoreService::plan_from_manifest:791`,
    /// then `RestoreService::run_logical:575` and `RestoreService::plan_logical:707`
    /// (`restore_action_hash(...)`); the plan is persisted at `:679-683` and is read
    /// back by `crates/eliot-engine/tests/operations_runbook.rs:190-193`.
    /// Judged individually: this is the approval binding the restore cutover is
    /// authorized against, so `I05-13:33` (`Human/System Owner authorizes cutover;`)
    /// and `APPENDIX-P:12` forbid letting an absent key decode as "no binding".
    /// `RestorePlan` carries no version field, so no enclosing version selects a
    /// historical reading (`I05-22:4`) and no versioned compatibility owner is
    /// recorded; explicit `null` remains legal per `I05-16:46`.
    /// KNOWN GAP, not repaired here: `RestoreService::run` (`:514`) still emits
    /// `exact_action_hash: None` alongside `RestoreStatus::RestoredToNewRoot`
    /// (`:512`, `:523`). That producer-side repair is card DO NOT and is owned by
    /// no issue; this decoder now makes such a record detectable instead of silent.
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub exact_action_hash: Option<String>,
    pub checks: Vec<RestoreCheck>,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreMode {
    VerifyOnly,
    RestoreToNewRoot,
    PromoteRestoredRoot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreCheck {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreReceipt {
    pub restore_receipt_id: String,
    pub restore_plan_id: String,
    pub status: RestoreStatus,
    pub target_data_root: PathRef,
    pub verified_manifest: bool,
    pub verified_checksums: bool,
    pub restored_objects: u64,
    pub restored_blobs: u64,
    /// `sd7`. Effect-bearing current form: the canonical key is now REQUIRED and an
    /// omitted `exact_action_hash` refuses. All three `RestoreReceipt`
    /// constructors write the key unconditionally —
    /// `crates/eliot-engine/src/safety.rs::RestoreService::verify:471` (`:480`,
    /// `status: VerifiedOnly` at `:474`, `dry_run: true` at `:481`),
    /// `RestoreService::run:514` (`:523`), and `RestoreService::run_logical:662`
    /// (`:671`, `Some(exact_action_hash)`); `run_logical` is the only one that
    /// persists `restore-evidence/restore-receipt.json` (`:679-683`).
    /// Judged individually: a restore receipt is the durable proof that an
    /// external effect was authorized by an exact action, so per `APPENDIX-P:12`
    /// and `A0-03:9` (`a false VERIFIED_COMPLETE or other proof claim;`) an
    /// absent key may not decode as "no approval was bound". `RestoreReceipt`
    /// carries no version field, so no enclosing version selects a historical
    /// reading (`I05-22:4`) and no versioned compatibility owner is recorded;
    /// `I05-16:46` keeps an explicit `null` legal, which is what `verify` and
    /// `run` legitimately emit for a non-mutating receipt.
    /// KNOWN GAP, not repaired here and recorded against this row:
    /// `RestoreService::rollback_isolated` (`:711`) reads this same receipt at
    /// `:728-733` but asserts no `exact_action_hash` and no `dry_run == false`.
    /// That producer-side repair is card DO NOT and is owned by no issue.
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub exact_action_hash: Option<String>,
    pub dry_run: bool,
    pub started_at: OffsetDateTime,
    pub finished_at: OffsetDateTime,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRollbackReceipt {
    pub rollback_receipt_id: String,
    pub target_data_root: PathRef,
    pub quarantined_root: Option<PathRef>,
    pub exact_action_hash: String,
    pub status: String,
    pub dry_run: bool,
    pub finished_at: OffsetDateTime,
    pub errors: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreStatus {
    VerifiedOnly,
    RestoredToNewRoot,
    FailedManifest,
    FailedChecksum,
    FailedWrite,
    RejectedUnsafeTarget,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreReport {
    pub component: String,
    pub plan: RestorePlan,
    pub receipt: RestoreReceipt,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportBundle {
    pub export_id: String,
    pub project_id: Option<ProjectId>,
    pub created_at: OffsetDateTime,
    pub export_kind: ExportKind,
    pub manifest_ref: String,
    pub payload_refs: Vec<String>,
    pub redaction_profile: RedactionProfile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportKind {
    ProjectEvidence,
    ReportsOnly,
    MemorySnapshot,
    IncidentBundle,
    DebugBundle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionProfile {
    InternalMetadataOnly,
    RedactedForExternal,
    IncidentAdmin,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportPlan {
    pub import_plan_id: String,
    pub import_root: PathRef,
    pub import_kind: ImportKind,
    pub taint: TaintClass,
    pub validation: ImportValidation,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportKind {
    LegacyEliotExport,
    ReportsBundle,
    MemoryCandidateBundle,
    ExternalEvidenceBundle,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportValidation {
    pub admin_only: bool,
    pub accepted: bool,
    pub raw_surql_rejected: bool,
    pub maintenance_mode_required: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalImportEnvelope {
    pub import_id: String,
    pub idempotency_key: String,
    pub source_ref: PathRef,
    pub source_artifact_id: String,
    pub artifact_kind: String,
    pub project_ref: Option<String>,
    pub task_ref: Option<String>,
    pub payload: serde_json::Value,
    pub taint: TaintClass,
    pub provenance: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalImportQuarantine {
    pub source_ref: PathRef,
    pub source_artifact_id: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalImportPreview {
    pub preview_id: String,
    pub source_root: PathRef,
    pub plan_hash: String,
    pub target_store_fingerprint: String,
    pub accepted: Vec<HistoricalImportEnvelope>,
    pub quarantined: Vec<HistoricalImportQuarantine>,
    pub already_imported: Vec<String>,
    pub raw_surql_rejected: bool,
    pub maintenance_mode_required: bool,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalImportStatus {
    PreviewOnly,
    Imported,
    ImportedWithQuarantine,
    RejectedApproval,
    RejectedMaintenanceMode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalImportReceipt {
    pub receipt_id: String,
    pub preview_id: String,
    pub plan_hash: String,
    pub status: HistoricalImportStatus,
    pub imported_ids: Vec<String>,
    pub already_imported_ids: Vec<String>,
    pub quarantine_refs: Vec<PathRef>,
    pub write_receipt_refs: Vec<WriteReceiptRef>,
    pub finished_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobManifest {
    pub manifest_id: String,
    pub generated_at: OffsetDateTime,
    pub blob_root: PathRef,
    pub blobs: Vec<BlobManifestEntry>,
    pub total_bytes: u64,
    pub checksum_algorithm: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobManifestEntry {
    pub blob_hash: String,
    pub path: PathRef,
    pub size_bytes: u64,
    pub content_type: Option<String>,
    pub compression: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobRetentionClass {
    Standard,
    AuditRetained,
    LegalHold,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobReachabilityRef {
    pub blob_hash: String,
    pub canonical_record_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobRetentionRef {
    pub blob_hash: String,
    pub canonical_record_ref: String,
    pub retention: BlobRetentionClass,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobReferenceSnapshot {
    pub snapshot_id: String,
    pub source_store: String,
    pub source_revision: String,
    pub scope: String,
    pub query_hash: String,
    pub created_at: OffsetDateTime,
    pub complete: bool,
    pub records_scanned: u32,
    pub reachable_refs: Vec<BlobReachabilityRef>,
    pub retention_refs: Vec<BlobRetentionRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobGcPlan {
    pub gc_plan_id: String,
    pub generated_at: OffsetDateTime,
    pub manifest_hash: String,
    pub reference_snapshot: BlobReferenceSnapshot,
    pub reachable: Vec<String>,
    pub unreachable_grace: Vec<String>,
    pub unreachable_deletable: Vec<String>,
    pub protected: Vec<String>,
    pub estimated_reclaim_bytes: u64,
    pub scan_sequence: u8,
    pub approval_hash: String,
    pub deletion_candidates: Vec<BlobDeletionCandidate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobDeletionCandidate {
    pub blob_hash: String,
    pub path: PathRef,
    pub size_bytes: u64,
    pub observed_scans: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobGcReceipt {
    pub gc_receipt_id: String,
    pub gc_plan_id: String,
    pub deleted_blobs: Vec<String>,
    pub reclaimed_bytes: u64,
    pub skipped: Vec<String>,
    pub status: BlobGcStatus,
    pub dry_run: bool,
    pub finished_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobGcStatus {
    DryRun,
    Succeeded,
    RefusedUnderLoad,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobReport {
    pub component: String,
    pub manifest: Option<BlobManifest>,
    pub gc_plan: Option<BlobGcPlan>,
    pub gc_receipt: Option<BlobGcReceipt>,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceJob {
    pub job_id: String,
    pub job_kind: MaintenanceJobKind,
    pub project_id: Option<ProjectId>,
    pub status: MaintenanceJobStatus,
    pub requested_by: String,
    pub dry_run: bool,
    pub started_at: Option<OffsetDateTime>,
    pub finished_at: Option<OffsetDateTime>,
    pub receipt_ref: Option<String>,
    pub write_receipt: Option<WriteReceiptRef>,
    pub errors: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceJobKind {
    Backup,
    RestoreVerify,
    Export,
    ImportValidate,
    BlobGc,
    Doctor,
    IncidentReview,
    ConfigSnapshot,
    PolicySnapshot,
    UlCapsuleMaintenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceJobStatus {
    Registered,
    Running,
    Succeeded,
    SucceededDryRun,
    Failed,
    Paused,
    Denied,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentRecord {
    pub incident_id: String,
    pub severity: IncidentSeverity,
    pub status: IncidentStatus,
    pub kind: IncidentKind,
    pub project_id: Option<ProjectId>,
    pub affected_surfaces: Vec<String>,
    pub opened_at: OffsetDateTime,
    pub acknowledged_at: Option<OffsetDateTime>,
    pub closed_at: Option<OffsetDateTime>,
    pub evidence_refs: Vec<String>,
    pub last_known_safe_refs: Vec<String>,
    pub recovery_commands: Vec<String>,
    pub summary: String,
    /// `sd8` - DISPOSITION ROW, judged individually against `I05-16:44` and
    /// `I05-16:46`, and the
    /// retained `Option` is a LEGITIMATE EXPLICIT-UNKNOWN, not an effect-bearing
    /// binding, so this member is deliberately NOT given the refusing decoder that
    /// `sd1`..`sd7` carry.
    ///
    /// Reason 1 — the member genuinely does not apply to most records. There are
    /// thirteen `IncidentKind` variants and only one of them
    /// (`IncidentKind::CampaignProviderCallBudgetExceeded`) has campaign integrity
    /// facts; the general writer `crates/eliot-engine/src/safety.rs::IncidentService::open:1740`
    /// emits `campaign_integrity: None` at `:1768` for every other kind, and the
    /// campaign writer `crates/eliot-engine/src/delegation_calibration.rs::CampaignIntegrityReconciliationService`
    /// emits `campaign_integrity: Some(details)` at `:636` for that one. Both always
    /// write the key (an `Option<T>` with no `skip_serializing_if`), so current bytes
    /// are unaffected either way.
    ///
    /// Reason 2 — an omission cannot create a false proof claim here, which is the
    /// only situation `A0-03` requires fail-closed for (`an untraceable irreversible
    /// or external effect;`, `a false VERIFIED_COMPLETE or other proof claim;`).
    /// The only reader is `crates/eliot-engine/src/delegation_calibration.rs:1247-1256`,
    /// which credits containment only when the details are present AND their status
    /// is `Contained`/`Resolved`; an omitted key decodes to the `None` branch, so
    /// `campaign_integrity_contained` stays false and `integrity_blocked`
    /// (`:1258`) forces `DelegationPromotionReadinessVerdict::BlockedByIntegrity`
    /// (`:1266-1267`). The default direction is therefore A0-03's own
    /// `quarantine`/`escalation` class, never an unearned promotion.
    ///
    /// Reason 3 — the omission already means `unknown` in the sanctioned sense:
    /// `I05-16:44` (`Absence of a closure or coverage record means `unknown`, not
    /// unrestricted/complete.`) is exactly what the containment gate implements, and
    /// `I05-16:46` (`Fields that do not apply remain explicit `None`; they are not
    /// silently omitted from the semantic model.`) is what a present-and-`null` key
    /// expresses. Both an omitted key and an explicit `null` decode to `None` here
    /// and neither is reinterpreted as false or zero.
    ///
    /// Reason 4 — `APPENDIX-P:12` enumerates the never-silently-defaulted classes
    /// (`authority, scope, effect, privacy, ordering and receipt fields`); this is
    /// none of them. It is containment evidence attached to an incident report, and
    /// the record's own identity, status, timestamps and evidence handles remain
    /// required members with no default.
    ///
    /// What changed and what did not: the redundant bare `#[serde(default)]` is
    /// removed so that this file carries no defaulted member, but this is NOT a
    /// refusal. Plain removal is behaviour-neutral for an `Option<T>` — `serde_derive`
    /// reaches `missing_field`, whose `MissingFieldDeserializer` answers
    /// `deserialize_option` with `visit_none()` — so the decoded bytes and the
    /// decoded value are identical before and after. Deliberately NO
    /// `deserialize_with = "deserialize_required_nullable"` is applied here, so an
    /// omitted `campaign_integrity` still decodes to `None`; that is asserted
    /// directly in this module's tests. No versioned compatibility owner, no
    /// `#[serde(alias)]`, no legacy schema name and no proof-ceiling value are
    /// invented: none is needed, because the omission is read as explicit unknown
    /// rather than as an accepted historical form.
    pub campaign_integrity: Option<crate::delegation_calibration::CampaignIntegrityIncidentDetails>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    Info,
    Warning,
    Degraded,
    Blocking,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    Acknowledged,
    Mitigated,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentKind {
    BackupManifestMismatch,
    RestoreIntegrityFailure,
    BlobChecksumMismatch,
    WriterUnavailable,
    DbUnavailable,
    OutboxMismatch,
    DeadLetterThreshold,
    DirectDbBypassDetected,
    InvalidConfig,
    InvalidPolicy,
    RepeatedServiceFailure,
    UnknownSequenceBase,
    CampaignProviderCallBudgetExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentReport {
    pub component: String,
    pub incidents: Vec<IncidentRecord>,
    pub lockdown_active: bool,
    pub generated_at: OffsetDateTime,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorReport {
    pub component: String,
    pub data_root_validation: DataRootValidation,
    pub gitignore_excludes_live_roots: bool,
    pub report_roots_writable: bool,
    pub log_roots_writable: bool,
    pub blob_manifest_consistent: bool,
    pub open_incidents: usize,
    pub stale_locks: Vec<String>,
    pub stale_test_processes_warning: Option<String>,
    pub memory_pressure: MemoryPressureReport,
    pub open_skill_curation_proposals: usize,
    pub open_replay_requirements: usize,
    pub sdk_absent: bool,
    pub rsa_absent: bool,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationsCheck {
    pub name: String,
    pub passed: bool,
    pub blocking: bool,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationsDoctorReport {
    pub component: String,
    pub status: String,
    pub checks: Vec<OperationsCheck>,
    pub base_report: DoctorReport,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionCutoverManifest {
    pub manifest_id: String,
    pub status: String,
    pub current_data_root: PathRef,
    pub proposed_data_root: PathRef,
    pub config_path: PathRef,
    pub executable_path: PathRef,
    pub preflight: Vec<OperationsCheck>,
    pub exact_changes: Vec<String>,
    pub operator_commands: Vec<String>,
    pub rollback_commands: Vec<String>,
    pub approval_required: bool,
    pub dry_run: bool,
    pub generated_at: OffsetDateTime,
}

#[cfg(test)]
// Tests may `expect`: a failed expectation is the test failing, not a production
// panic path. Crate convention for test modules, as at `memory.rs:3615`.
#[allow(clippy::expect_used)]
mod tests {
    //! Rows `sd1`..`sd8` of issue #938. Every input below is RAW BYTES handed
    //! straight to `serde_json::from_str`; a `serde_json::Value` intermediate is
    //! deliberately avoided because it would collapse a repeated member before
    //! the decoder sees it.

    use super::{
        BackupManifest, BackupReport, IncidentRecord, RestorePlan, RestoreReceipt, RestoreReport,
    };

    const TS: &str = "2026-01-02T03:04:05Z";

    /// Canonical `BackupManifest` with all three `sd1`..`sd3` keys present and
    /// populated. `manifest_json` substitutes one key at a time so each row is
    /// exercised on its own document rather than through a shared blob.
    fn manifest_json(
        surreal_source_endpoint: &str,
        surreal_source_storage_ref: &str,
        blob_payload_root: &str,
    ) -> String {
        format!(
            concat!(
                "{{\"backup_id\":\"backup-1\",\"created_at\":\"", "{ts}\",",
                "\"source_data_root\":\"/src\",\"backup_root\":\"/backup\",",
                "\"backup_kind\":\"logical_export\",\"governor_version\":\"1\",",
                "\"schema_version\":\"1\",\"policy_snapshot_refs\":[],\"config_snapshot_refs\":[],",
                "\"surreal_export_ref\":null,\"surreal_export_status\":\"validated\",",
                "\"surreal_source_endpoint\":{endpoint},",
                "\"surreal_source_storage_ref\":{storage},",
                "\"control_wal_snapshot_ref\":null,\"blob_manifest_ref\":\"/backup/blob-manifest.json\",",
                "\"blob_payload_root\":{payload},\"blob_payloads\":[],\"report_manifest_ref\":null,",
                "\"checksums\":[],\"copied_live_db_files\":false,\"dry_run\":false,\"warnings\":[]}}"
            ),
            ts = TS,
            endpoint = surreal_source_endpoint,
            storage = surreal_source_storage_ref,
            payload = blob_payload_root
        )
    }

    const ENDPOINT: &str = "\"ws://source:8000/rpc\"";
    const ENDPOINT_NULL: &str = "null";
    const STORAGE: &str = "\"/src/storage\"";
    const STORAGE_NULL: &str = "null";
    const PAYLOAD: &str = "\"/backup/blob-payloads\"";
    const PAYLOAD_NULL: &str = "null";

    /// Canonical `RestorePlan` with all three `sd4`..`sd6` keys supplied.
    fn plan_json(
        target_endpoint: &str,
        target_storage_ref: &str,
        exact_action_hash: &str,
    ) -> String {
        format!(
            concat!(
                "{{\"restore_plan_id\":\"restore-plan-1\",\"backup_id\":\"backup-1\",",
                "\"backup_manifest_ref\":\"/backup/manifest.json\",\"target_data_root\":\"/target\",",
                "\"restore_mode\":\"verify_only\",\"target_endpoint\":{endpoint},",
                "\"target_storage_ref\":{storage},\"exact_action_hash\":{hash},",
                "\"checks\":[],\"created_at\":\"", "{ts}\"}}"
            ),
            endpoint = target_endpoint,
            storage = target_storage_ref,
            hash = exact_action_hash,
            ts = TS
        )
    }

    const HASH: &str = "\"action-hash-1\"";
    const HASH_NULL: &str = "null";

    fn receipt_json(exact_action_hash: &str) -> String {
        format!(
            concat!(
                "{{\"restore_receipt_id\":\"restore-receipt-1\",\"restore_plan_id\":\"restore-plan-1\",",
                "\"status\":\"verified_only\",\"target_data_root\":\"/target\",",
                "\"verified_manifest\":true,\"verified_checksums\":true,",
                "\"restored_objects\":0,\"restored_blobs\":0,\"exact_action_hash\":{hash},",
                "\"dry_run\":true,\"started_at\":\"", "{ts}\",\"finished_at\":\"", "{ts}\",\"errors\":[]}}"
            ),
            hash = exact_action_hash,
            ts = TS
        )
    }

    const INCIDENT_TAIL: &str = concat!(
        ",\"affected_surfaces\":[],\"opened_at\":\"2026-01-02T03:04:05Z\",",
        "\"acknowledged_at\":null,\"closed_at\":null,\"evidence_refs\":[],",
        "\"last_known_safe_refs\":[],\"recovery_commands\":[],\"summary\":\"s\""
    );

    fn incident_json(campaign_integrity: &str) -> String {
        format!(
            concat!(
                "{{\"incident_id\":\"incident-1\",\"severity\":\"critical\",\"status\":\"open\",",
                "\"kind\":\"campaign_provider_call_budget_exceeded\",\"project_id\":null",
                "{tail},\"campaign_integrity\":{details}}}"
            ),
            tail = INCIDENT_TAIL,
            details = campaign_integrity
        )
    }

    // ---- sd1: BackupManifest::surreal_source_endpoint ----

    #[test]
    fn sd1_omitted_surreal_source_endpoint_refuses() {
        let raw = manifest_json(ENDPOINT_NULL, STORAGE, PAYLOAD).replace(
            "\"surreal_source_endpoint\":null,",
            "",
        );
        let error = serde_json::from_str::<BackupManifest>(&raw)
            .expect_err("an omitted sd1 key must refuse");
        assert!(
            error.to_string().contains("surreal_source_endpoint"),
            "error must name the missing key, got: {error}"
        );
    }

    #[test]
    fn sd1_explicit_null_surreal_source_endpoint_decodes_to_none() {
        let raw = manifest_json(ENDPOINT_NULL, STORAGE, PAYLOAD);
        let manifest: BackupManifest = serde_json::from_str(&raw).expect("explicit null is legal");
        assert_eq!(manifest.surreal_source_endpoint, None);
        assert_eq!(
            serde_json::to_string(&manifest).expect("re-serialize"),
            raw,
            "the Serialize side must be byte-identical to the input"
        );
    }

    #[test]
    fn sd1_populated_surreal_source_endpoint_round_trips_byte_for_byte() {
        let raw = manifest_json(ENDPOINT, STORAGE, PAYLOAD);
        let manifest: BackupManifest = serde_json::from_str(&raw).expect("populated key decodes");
        assert_eq!(manifest.surreal_source_endpoint.as_deref(), Some("ws://source:8000/rpc"));
        assert_eq!(
            serde_json::to_string(&manifest).expect("re-serialize"),
            raw
        );
    }

    // ---- sd2: BackupManifest::surreal_source_storage_ref ----

    #[test]
    fn sd2_omitted_surreal_source_storage_ref_refuses() {
        let raw = manifest_json(ENDPOINT, STORAGE_NULL, PAYLOAD).replace(
            "\"surreal_source_storage_ref\":null,",
            "",
        );
        let error = serde_json::from_str::<BackupManifest>(&raw)
            .expect_err("an omitted sd2 key must refuse");
        assert!(
            error.to_string().contains("surreal_source_storage_ref"),
            "error must name the missing key, got: {error}"
        );
    }

    #[test]
    fn sd2_explicit_null_surreal_source_storage_ref_decodes_to_none() {
        let raw = manifest_json(ENDPOINT, STORAGE_NULL, PAYLOAD);
        let manifest: BackupManifest = serde_json::from_str(&raw).expect("explicit null is legal");
        assert_eq!(manifest.surreal_source_storage_ref, None);
        assert_eq!(
            serde_json::to_string(&manifest).expect("re-serialize"),
            raw
        );
    }

    #[test]
    fn sd2_populated_surreal_source_storage_ref_round_trips_byte_for_byte() {
        let raw = manifest_json(ENDPOINT, STORAGE, PAYLOAD);
        let manifest: BackupManifest = serde_json::from_str(&raw).expect("populated key decodes");
        assert_eq!(manifest.surreal_source_storage_ref.as_deref(), Some("/src/storage"));
        assert_eq!(
            serde_json::to_string(&manifest).expect("re-serialize"),
            raw
        );
    }

    // ---- sd3: BackupManifest::blob_payload_root ----

    #[test]
    fn sd3_omitted_blob_payload_root_refuses() {
        let raw = manifest_json(ENDPOINT, STORAGE, PAYLOAD_NULL)
            .replace("\"blob_payload_root\":null,", "");
        let error = serde_json::from_str::<BackupManifest>(&raw)
            .expect_err("an omitted sd3 key must refuse");
        assert!(
            error.to_string().contains("blob_payload_root"),
            "error must name the missing key, got: {error}"
        );
    }

    #[test]
    fn sd3_explicit_null_blob_payload_root_decodes_to_none() {
        // The only producer emits `null` here for a dry run
        // (`build_backup:77-83`, `:152`), so an explicit `null` must stay legal.
        let raw = manifest_json(ENDPOINT, STORAGE, PAYLOAD_NULL);
        let manifest: BackupManifest = serde_json::from_str(&raw).expect("explicit null is legal");
        assert_eq!(manifest.blob_payload_root, None);
        assert_eq!(
            serde_json::to_string(&manifest).expect("re-serialize"),
            raw
        );
    }

    #[test]
    fn sd3_populated_blob_payload_root_round_trips_byte_for_byte() {
        let raw = manifest_json(ENDPOINT, STORAGE, PAYLOAD);
        let manifest: BackupManifest = serde_json::from_str(&raw).expect("populated key decodes");
        assert_eq!(
            manifest.blob_payload_root.as_deref(),
            Some("/backup/blob-payloads")
        );
        assert_eq!(
            serde_json::to_string(&manifest).expect("re-serialize"),
            raw
        );
    }

    // ---- sd4: RestorePlan::target_endpoint ----

    #[test]
    fn sd4_omitted_target_endpoint_refuses() {
        let raw = plan_json(ENDPOINT_NULL, STORAGE, HASH).replace("\"target_endpoint\":null,", "");
        let error = serde_json::from_str::<RestorePlan>(&raw)
            .expect_err("an omitted sd4 key must refuse");
        assert!(
            error.to_string().contains("target_endpoint"),
            "error must name the missing key, got: {error}"
        );
    }

    #[test]
    fn sd4_explicit_null_target_endpoint_decodes_to_none() {
        let raw = plan_json(ENDPOINT_NULL, STORAGE, HASH);
        let plan: RestorePlan = serde_json::from_str(&raw).expect("explicit null is legal");
        assert_eq!(plan.target_endpoint, None);
        assert_eq!(
            serde_json::to_string(&plan).expect("re-serialize"),
            raw
        );
    }

    #[test]
    fn sd4_populated_target_endpoint_round_trips_byte_for_byte() {
        let raw = plan_json(ENDPOINT, STORAGE, HASH);
        let plan: RestorePlan = serde_json::from_str(&raw).expect("populated key decodes");
        assert_eq!(plan.target_endpoint.as_deref(), Some("ws://source:8000/rpc"));
        assert_eq!(
            serde_json::to_string(&plan).expect("re-serialize"),
            raw
        );
    }

    // ---- sd5: RestorePlan::target_storage_ref ----

    #[test]
    fn sd5_omitted_target_storage_ref_refuses() {
        let raw = plan_json(ENDPOINT, STORAGE_NULL, HASH)
            .replace("\"target_storage_ref\":null,", "");
        let error = serde_json::from_str::<RestorePlan>(&raw)
            .expect_err("an omitted sd5 key must refuse");
        assert!(
            error.to_string().contains("target_storage_ref"),
            "error must name the missing key, got: {error}"
        );
    }

    #[test]
    fn sd5_explicit_null_target_storage_ref_decodes_to_none() {
        let raw = plan_json(ENDPOINT, STORAGE_NULL, HASH);
        let plan: RestorePlan = serde_json::from_str(&raw).expect("explicit null is legal");
        assert_eq!(plan.target_storage_ref, None);
        assert_eq!(
            serde_json::to_string(&plan).expect("re-serialize"),
            raw
        );
    }

    #[test]
    fn sd5_populated_target_storage_ref_round_trips_byte_for_byte() {
        let raw = plan_json(ENDPOINT, STORAGE, HASH);
        let plan: RestorePlan = serde_json::from_str(&raw).expect("populated key decodes");
        assert_eq!(plan.target_storage_ref.as_deref(), Some("/src/storage"));
        assert_eq!(
            serde_json::to_string(&plan).expect("re-serialize"),
            raw
        );
    }

    // ---- sd6: RestorePlan::exact_action_hash ----

    #[test]
    fn sd6_omitted_exact_action_hash_refuses() {
        let raw =
            plan_json(ENDPOINT, STORAGE, HASH_NULL).replace("\"exact_action_hash\":null,", "");
        let error = serde_json::from_str::<RestorePlan>(&raw)
            .expect_err("an omitted sd6 key must refuse");
        assert!(
            error.to_string().contains("exact_action_hash"),
            "error must name the missing key, got: {error}"
        );
    }

    #[test]
    fn sd6_explicit_null_exact_action_hash_decodes_to_none() {
        let raw = plan_json(ENDPOINT, STORAGE, HASH_NULL);
        let plan: RestorePlan = serde_json::from_str(&raw).expect("explicit null is legal");
        assert_eq!(plan.exact_action_hash, None);
        assert_eq!(
            serde_json::to_string(&plan).expect("re-serialize"),
            raw
        );
    }

    #[test]
    fn sd6_populated_exact_action_hash_round_trips_byte_for_byte() {
        let raw = plan_json(ENDPOINT, STORAGE, HASH);
        let plan: RestorePlan = serde_json::from_str(&raw).expect("populated key decodes");
        assert_eq!(plan.exact_action_hash.as_deref(), Some("action-hash-1"));
        assert_eq!(
            serde_json::to_string(&plan).expect("re-serialize"),
            raw
        );
    }

    // ---- sd7: RestoreReceipt::exact_action_hash ----

    #[test]
    fn sd7_omitted_exact_action_hash_refuses() {
        let raw = receipt_json(HASH_NULL).replace("\"exact_action_hash\":null,", "");
        let error = serde_json::from_str::<RestoreReceipt>(&raw)
            .expect_err("an omitted sd7 key must refuse");
        assert!(
            error.to_string().contains("exact_action_hash"),
            "error must name the missing key, got: {error}"
        );
    }

    #[test]
    fn sd7_explicit_null_exact_action_hash_decodes_to_none() {
        // `RestoreService::verify:480` and `RestoreService::run:523` legitimately
        // emit `None`, so an explicit `null` must stay legal.
        let raw = receipt_json(HASH_NULL);
        let receipt: RestoreReceipt = serde_json::from_str(&raw).expect("explicit null is legal");
        assert_eq!(receipt.exact_action_hash, None);
        assert_eq!(
            serde_json::to_string(&receipt).expect("re-serialize"),
            raw
        );
    }

    #[test]
    fn sd7_populated_exact_action_hash_round_trips_byte_for_byte() {
        let raw = receipt_json(HASH);
        let receipt: RestoreReceipt = serde_json::from_str(&raw).expect("populated key decodes");
        assert_eq!(receipt.exact_action_hash.as_deref(), Some("action-hash-1"));
        assert_eq!(
            serde_json::to_string(&receipt).expect("re-serialize"),
            raw
        );
    }

    // ---- sd8: IncidentRecord::campaign_integrity (DISPOSITION) ----
    //
    // Decided disposition: the retained `Option` is a legitimate explicit-unknown
    // per `I05-16:46` (`Fields that do not apply remain explicit `None`; they are
    // not silently omitted from the semantic model.`), NOT an effect-bearing
    // binding that must refuse. It is deliberately NOT given
    // `deserialize_required_nullable`, so BOTH an omitted key and an explicit
    // `null` must still decode to `None`. See the member's doc comment for the
    // full argument (reasons 1-4).

    #[test]
    fn sd8_omitted_campaign_integrity_still_decodes_to_none_as_explicit_unknown() {
        // Whole-document string equality is IMPOSSIBLE here and is deliberately
        // not asserted: `IncidentRecord` carries no `skip_serializing_if`, so the
        // encoder always emits `campaign_integrity` and no encoding of a record
        // decoded from a key-absent document can equal that document. What this
        // test is actually for is the sd8 disposition itself, so it asserts the
        // decode and the decoded value, and proves the Serialize side is
        // untouched by checking the re-encoded bytes equal the CANONICAL document
        // (the same record with the key present and explicitly `null`).
        let without_key = incident_json("null").replace(",\"campaign_integrity\":null", "");
        let incident: IncidentRecord = serde_json::from_str(&without_key)
            .expect("sd8 disposition: an omitted key is an explicit unknown, not a refusal");
        assert_eq!(incident.campaign_integrity, None);
        assert_eq!(
            serde_json::to_string(&incident).expect("re-serialize"),
            incident_json("null"),
            "an omitted key decodes to the same record an explicit null encodes to"
        );
    }

    #[test]
    fn sd8_explicit_null_campaign_integrity_decodes_to_none() {
        let raw = incident_json("null");
        let incident: IncidentRecord = serde_json::from_str(&raw).expect("explicit null is legal");
        assert_eq!(incident.campaign_integrity, None);
        assert_eq!(
            serde_json::to_string(&incident).expect("re-serialize"),
            raw
        );
    }

    // ---- survivors of the existing decoders ----

    /// The untouched `deserialize_manifest_schema_version` pin still refuses a
    /// misselected version on an otherwise complete manifest.
    #[test]
    fn misselected_manifest_schema_version_still_refuses() {
        let raw = manifest_json(ENDPOINT, STORAGE, PAYLOAD)
            .replace("\"schema_version\":\"1\"", "\"schema_version\":\"0\"");
        let error = serde_json::from_str::<BackupManifest>(&raw)
            .expect_err("a misselected schema_version must refuse");
        assert!(
            error.to_string().contains("unsupported backup manifest schema_version"),
            "error must come from the existing pin, got: {error}"
        );
    }

    /// The derived parent decoders are not broken by the new `deserialize_with`
    /// attributes on their nested members.
    #[test]
    fn backup_report_with_nested_manifest_decodes() {
        let raw = format!(
            concat!(
                "{{\"component\":\"backup\",\"manifest\":{manifest},\"receipt\":",
                "{{\"backup_id\":\"backup-1\",\"status\":\"succeeded\",",
                "\"manifest_ref\":\"/backup/manifest.json\",\"bytes_written\":1,",
                "\"objects_written\":1,\"started_at\":\"", "{ts}\",\"finished_at\":\"", "{ts}\",",
                "\"errors\":[]}},\"generated_at\":\"", "{ts}\"}}"
            ),
            manifest = manifest_json(ENDPOINT, STORAGE, PAYLOAD),
            ts = TS
        );
        let report: BackupReport = serde_json::from_str(&raw).expect("BackupReport decodes");
        assert_eq!(
            report.manifest.surreal_source_endpoint.as_deref(),
            Some("ws://source:8000/rpc")
        );
        assert_eq!(report.manifest.blob_payload_root.as_deref(), Some("/backup/blob-payloads"));
        assert_eq!(
            serde_json::to_string(&report).expect("re-serialize"),
            raw
        );
    }

    #[test]
    fn restore_report_with_nested_plan_and_receipt_decodes() {
        let raw = format!(
            concat!(
                "{{\"component\":\"restore\",\"plan\":{plan},\"receipt\":{receipt},",
                "\"generated_at\":\"", "{ts}\"}}"
            ),
            plan = plan_json(ENDPOINT, STORAGE, HASH),
            receipt = receipt_json(HASH),
            ts = TS
        );
        let report: RestoreReport = serde_json::from_str(&raw).expect("RestoreReport decodes");
        assert_eq!(report.plan.exact_action_hash.as_deref(), Some("action-hash-1"));
        assert_eq!(report.receipt.exact_action_hash.as_deref(), Some("action-hash-1"));
        assert_eq!(
            serde_json::to_string(&report).expect("re-serialize"),
            raw
        );
    }
}