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

/// Decoder for an effect-bearing field that is required on the wire and
/// explicitly nullable.
///
/// `Option<T>` under derived `Deserialize` already decodes an *absent* key as
/// `None`, so `#[serde(default)]` (or a bare `Option`) makes omission
/// indistinguishable from an explicitly recorded "there is none". Carrying
/// `#[serde(deserialize_with = "deserialize_required_nullable")]` and *no*
/// `#[serde(default)]` makes the derived visitor reject the missing key with
/// the typed missing-field error first, while this body keeps handling a
/// present value or an explicit `null` exactly as before.
///
/// This is the same treatment `provider_invocation.rs` already gives its ten
/// required-nullable outcome fields; there is no second pattern to invent.
fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Decoder: derived and closed. The three effect-bearing source bindings on
/// `BackupManifest` (`surreal_source_endpoint`, `surreal_source_storage_ref`,
/// `blob_payload_root`) carry `deserialize_with = "deserialize_required_nullable"`
/// and no `#[serde(default)]`, so an absent key is a typed missing-field
/// failure rather than a silent `None`.
///
/// Each of these is an isolation/effect fact, not telemetry. A silently
/// defaulted `surreal_source_endpoint` decodes as "no endpoint", and
/// `RestoreService::run_logical` (`crates/eliot-engine/src/safety.rs:556`)
/// compares `manifest.surreal_source_endpoint` against the restore target's
/// endpoint to decide endpoint isolation; a defaulted `blob_payload_root` is
/// the root `verify_blob_payload_manifest`
/// (`crates/eliot-engine/src/safety/backup.rs:386`) later resolves blob payload
/// paths under. An omitted key must therefore not decode as a recorded absence
/// (I5.16: absence stays explicit unknown, not a successful complete record;
/// Appendix P: authority/effect/receipt fields are never silently defaulted).
///
/// Compatibility: `BackupManifest` already carries the enclosing version that
/// selects the interpretation of its omissions —
/// `schema_version`, decode-pinned to `crate::SCHEMA_VERSION` by
/// `deserialize_manifest_schema_version` above. Only the adopted current
/// version decodes, so no supported historical form selects a legacy reading of
/// these three omissions and none is invented here; an older or unknown manifest
/// already refuses on its version before these fields are considered. The sole
/// writer, `BackupService::run`
/// (`crates/eliot-engine/src/safety/backup.rs:129`), always emits all three keys
/// including `null`, and `Serialize` is untouched, so accepted and emitted bytes
/// are unchanged. An explicit `null` remains reachable and still means "this
/// binding was not established"; only an *omitted* key refuses.
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
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub surreal_source_endpoint: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub surreal_source_storage_ref: Option<PathRef>,
    pub control_wal_snapshot_ref: Option<String>,
    pub blob_manifest_ref: String,
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

/// Decoder: derived and closed. The three effect-bearing target bindings on
/// `RestorePlan` (`target_endpoint`, `target_storage_ref`, `exact_action_hash`)
/// carry `deserialize_with = "deserialize_required_nullable"` and no
/// `#[serde(default)]`, so an absent key is a typed missing-field failure
/// rather than a silent `None`.
///
/// A restore plan names where a restore would write and which exact action was
/// approved for it. A silently defaulted `target_endpoint`/`target_storage_ref`
/// reads downstream as "no target endpoint" — the same value an isolated
/// filesystem-only restore legitimately carries — and a defaulted
/// `exact_action_hash` reads as "no action was bound". Those are effect
/// decisions, not telemetry, so an omitted key must not be able to reach them
/// (Appendix P; I5.16).
///
/// Compatibility: `RestorePlan` carries no enclosing `schema_version`, so there
/// is no version that selects a documented legacy interpretation of these three
/// omissions, and none is invented here (issue work item 4). Every current
/// producer sets all three explicitly, including `None`:
/// `RestoreService::plan_from_manifest` (`crates/eliot-engine/src/safety.rs:783`)
/// constructs the full literal with all three `None`, and
/// `RestoreService::plan_logical` / `run_logical` (`:705`, `:573`) overwrite all
/// three with the bound values before any restore runs. `Serialize` is
/// untouched, so emitted bytes are unchanged. A truncated or older plan that
/// omitted these keys now fails loudly instead of decoding as a plan with no
/// target binding and no approved action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorePlan {
    pub restore_plan_id: String,
    pub backup_id: String,
    pub backup_manifest_ref: String,
    pub target_data_root: PathRef,
    pub restore_mode: RestoreMode,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub target_endpoint: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub target_storage_ref: Option<PathRef>,
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

/// Decoder: derived and closed. `RestoreReceipt::exact_action_hash` carries
/// `deserialize_with = "deserialize_required_nullable"` and no
/// `#[serde(default)]`, so an absent key is a typed missing-field failure
/// rather than a silent `None`.
///
/// This is the audit's third named field: a restore receipt retained as durable
/// evidence is read back by the rollback effect path
/// (`RestoreService::rollback_isolated`, `crates/eliot-engine/src/safety.rs:728`,
/// decoding `restore-evidence/restore-receipt.json`). A silently defaulted
/// `exact_action_hash` decodes as `None` inside a success-shaped
/// `RestoredToNewRoot` receipt that an effect path then accepts, so a receipt
/// that never recorded which exact action was executed would present itself as a
/// complete one. Requiredness is the decoder's part of that contract; the
/// consumer-side status/mode validation the audit also asks for (a dry-run
/// receipt cannot stand for an executed restore, a deserialized receipt is not
/// owner issuance) is a `RestoreService` repair outside `eliot-types` and is not
/// claimed here.
///
/// Compatibility: no enclosing version selects a legacy reading of this
/// omission and none is invented. Every current producer sets it explicitly,
/// including `None`: `RestoreService::verify` (`:480`) and
/// `RestoreService::run` (`:523`) construct `None`, `run_logical` (`:671`)
/// constructs `Some(exact_action_hash)`, and `Serialize` is untouched, so
/// emitted bytes are unchanged.
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
    #[serde(default)]
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
