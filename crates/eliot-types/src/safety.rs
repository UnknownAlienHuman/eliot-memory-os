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

/// # An effect-bearing member is required on the wire (#938, defect 2)
///
/// Removing `#[serde(default)]` alone does NOT make an `Option<T>` member
/// required. Serde's missing-member fallback (`serde::private::de::missing_field`,
/// used by the derive when no `deserialize_with` is set) decodes an ABSENT member
/// as `None` whenever the field type is `Option<T>`. That is a silent default —
/// exactly what Appendix P forbids — and it would let a historical record that
/// omits its effect binding decode into a record that merely looks like an
/// effect record carrying an explicit `null`.
///
/// Supplying a `deserialize_with` function changes the missing-member path:
/// serde then reports a "missing field" naming that member, instead of
/// substituting `None`. An explicit `null` still reaches this function as a
/// PRESENT value and decodes
/// to `None`, so `null` remains the one admitted spelling of "does not apply"
/// (I5.16) and the two cases stay distinguishable at decode.
fn deserialize_required_member<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// # Effect-bearing safety records carry no silent wire default (#938, audit
/// comment 5917060171, defect 2)
///
/// Appendix P, "Rust public boundary interfaces": "authority, scope, effect,
/// privacy, ordering and receipt fields are never silently defaulted".
/// I5.27: "fields affecting authority, scope, ordering, privacy or effect
/// cannot be omitted/defaulted silently". I5.16: "Absence of a closure or
/// coverage record means `unknown`, not unrestricted/complete" and "Fields that
/// do not apply remain explicit `None`; they are not silently omitted from the
/// semantic model".
///
/// Every effect-bearing field of [`BackupManifest`], [`RestorePlan`] and
/// [`RestoreReceipt`] below is therefore REQUIRED on the wire. A producer must
/// write the field explicitly, and `null` is the only admitted spelling of "does
/// not apply"; an omitted member is refused at decode. There is no silent
/// default and no historical wire form to interpret: the sole admitted manifest
/// version is the current one, pinned at decode to [`crate::SCHEMA_VERSION`] by
/// [`deserialize_manifest_schema_version`], which refuses every other value, so
/// no versioned legacy interpretation of an omitted effect field exists and
/// none is admitted here.
///
/// A required member is still not a proof. `null` remains explicit `unknown`
/// (I5.16), so a success/effect-shaped record that does not carry its binding
/// cannot become an effect proof: the owner that consumes a decoded record
/// refuses it before any effect, and does not recompute a substitute binding.
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
    /// Required on the wire. `null` records that this backup sealed no logical
    /// source endpoint; a consumer must treat that as `unknown`, never as proof
    /// that a restore target is isolated from the backup source. Omitting the
    /// member is refused at decode (see `deserialize_required_member`).
    #[serde(deserialize_with = "deserialize_required_member")]
    pub surreal_source_endpoint: Option<String>,
    /// Required on the wire. `null` records that the logical source sealed no
    /// storage root (I5.16 explicit `None`, not an omission). Omitting the member
    /// is refused at decode (see `deserialize_required_member`).
    #[serde(deserialize_with = "deserialize_required_member")]
    pub surreal_source_storage_ref: Option<PathRef>,
    pub control_wal_snapshot_ref: Option<String>,
    pub blob_manifest_ref: String,
    /// Required on the wire. A completed (`dry_run == false`) backup must carry
    /// the payload root it actually copied; `null` is only the recorded absence
    /// for a planned backup, never a silent default for a completed one.
    /// Omitting the member is refused at decode (see
    /// `deserialize_required_member`).
    #[serde(deserialize_with = "deserialize_required_member")]
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
    /// Required on the wire. `null` records that this plan was sealed without a
    /// logical target endpoint; a consumer must treat that as `unknown`. Omitting
    /// the member is refused at decode (see `deserialize_required_member`).
    #[serde(deserialize_with = "deserialize_required_member")]
    pub target_endpoint: Option<String>,
    /// Required on the wire. `null` records that the plan was sealed without a
    /// logical target storage root (I5.16 explicit `None`, not an omission).
    /// Omitting the member is refused at decode (see
    /// `deserialize_required_member`).
    #[serde(deserialize_with = "deserialize_required_member")]
    pub target_storage_ref: Option<PathRef>,
    /// Required on the wire. `null` records that the owner sealed no exact
    /// action binding for this plan. A plan without that binding is explicit
    /// `unknown` about its effect identity (I5.27), so it can never authorize
    /// an effect on the strength of the record alone. Omitting the member is refused
    /// at decode (see `deserialize_required_member`).
    #[serde(deserialize_with = "deserialize_required_member")]
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
    /// Required on the wire. The owner always seals the exact action hash of an
    /// executed restore, so a receipt that omits it decodes as explicit `null`
    /// = `unknown`, never as a successfully bound effect record. A
    /// success/effect status is not admissible without this binding, and a
    /// dry-run receipt never stands for an executed restore: the consuming owner
    /// refuses both before any effect, comparing against the originally recorded
    /// value rather than a recomputed substitute. Omitting the member is refused
    /// at decode (see `deserialize_required_member`).
    #[serde(deserialize_with = "deserialize_required_member")]
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

#[cfg(test)]
mod tests {
    use super::{
        BackupKind, BackupManifest, RestoreMode, RestorePlan, RestoreReceipt, RestoreReport,
        RestoreStatus,
    };
    use crate::SCHEMA_VERSION;
    use serde_json::{Value, json};

    /// `OffsetDateTime` decodes from `time`'s tuple encoding: this crate's
    /// `time` build keeps `serde-human-readable` disabled, so the wire form of
    /// a timestamp is `(year, ordinal, hour, minute, second, nanosecond,
    /// offset_hours, offset_minutes, offset_seconds)`.
    fn wire_time() -> Value {
        json!([2026, 1, 0, 0, 0, 0, 0, 0, 0])
    }

    fn manifest_value() -> Value {
        json!({
            "backup_id": "backup-1",
            "created_at": wire_time(),
            "source_data_root": "C:/data",
            "backup_root": "C:/data/backups/backup-1",
            "backup_kind": "logical_export",
            "governor_version": "0.1.0",
            "schema_version": SCHEMA_VERSION,
            "policy_snapshot_refs": [],
            "config_snapshot_refs": [],
            "surreal_export_ref": "C:/data/backups/backup-1/surreal-export.surql",
            "surreal_export_status": "validated",
            "surreal_source_endpoint": "ws://127.0.0.1:8000",
            "surreal_source_storage_ref": "C:/data/store",
            "control_wal_snapshot_ref": null,
            "blob_manifest_ref": "C:/data/backups/backup-1/blob-manifest.json",
            "blob_payload_root": "C:/data/backups/backup-1/blob-payloads",
            "blob_payloads": [],
            "report_manifest_ref": null,
            "checksums": [],
            "copied_live_db_files": false,
            "dry_run": false,
            "warnings": [],
        })
    }

    fn plan_value() -> Value {
        json!({
            "restore_plan_id": "restore-plan-1",
            "backup_id": "backup-1",
            "backup_manifest_ref": "C:/data/backups/backup-1/manifest.json",
            "target_data_root": "C:/restore/restored",
            "restore_mode": "restore_to_new_root",
            "target_endpoint": "ws://127.0.0.1:9000",
            "target_storage_ref": "C:/restore/store",
            "exact_action_hash": "sealed-action",
            "checks": [],
            "created_at": wire_time(),
        })
    }

    fn receipt_value() -> Value {
        json!({
            "restore_receipt_id": "restore-receipt-1",
            "restore_plan_id": "restore-plan-1",
            "status": "restored_to_new_root",
            "target_data_root": "C:/restore/restored",
            "verified_manifest": true,
            "verified_checksums": true,
            "restored_objects": 1,
            "restored_blobs": 0,
            "exact_action_hash": "sealed-action",
            "dry_run": false,
            "started_at": wire_time(),
            "finished_at": wire_time(),
            "errors": [],
        })
    }

    /// The same record with exactly one member removed, returned by value so
    /// every call site hands an owned `Value` to `serde_json::from_value`
    /// (which takes `Value`, not `&Value`).
    ///
    /// The owned `Value` is moved out of the argument rather than borrowed and
    /// cloned: the clone was pure overhead on a fixture, and destructuring is
    /// also what refuses a non-object fixture here instead of the caller.
    ///
    /// The removal is checked rather than assumed: a misspelled member name
    /// would otherwise leave the fixture untouched and the caller's refusal
    /// would be attributed to the wrong cause.
    fn without(value: Value, field: &str) -> Value {
        let mut object = match value {
            Value::Object(object) => object,
            other => panic!("the fixture must be a JSON object, got: {other}"),
        };
        assert!(
            object.remove(field).is_some(),
            "the fixture must actually carry a `{field}` member to remove"
        );
        Value::Object(object)
    }

    /// Assert that `value` decodes as `T` only while it still carries `field`:
    /// the untouched fixture must decode, and the fixture missing exactly that
    /// one member must be refused by an error naming THAT member. Pinning the
    /// error text is what isolates the cause — a bare `is_err()` would also pass
    /// if some unrelated required member were absent from the fixture.
    fn assert_field_is_required<T>(value: Value, field: &str)
    where
        T: serde::de::DeserializeOwned + std::fmt::Debug,
    {
        serde_json::from_value::<T>(value.clone())
            .unwrap_or_else(|error| panic!("the complete fixture must decode: {error}"));

        let error = match serde_json::from_value::<T>(without(value, field)) {
            Ok(_) => panic!("an omitted effect-bearing member `{field}` must be refused"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            message.contains(&format!("missing field `{field}`")),
            "the refusal must name the absent member `{field}`, got: {message}"
        );
    }

    /// Positive case: a current owner-written record with every effect field
    /// present (explicit `null` included) decodes.
    #[test]
    fn owner_written_safety_records_with_explicit_effect_fields_decode()
    -> Result<(), serde_json::Error> {
        let manifest: BackupManifest = serde_json::from_value(manifest_value())?;
        assert_eq!(manifest.backup_kind, BackupKind::LogicalExport);
        assert_eq!(
            manifest.surreal_source_endpoint.as_deref(),
            Some("ws://127.0.0.1:8000")
        );
        assert!(manifest.blob_payload_root.is_some());
        let plan: RestorePlan = serde_json::from_value(plan_value())?;
        assert_eq!(plan.restore_mode, RestoreMode::RestoreToNewRoot);
        assert_eq!(plan.exact_action_hash.as_deref(), Some("sealed-action"));
        let receipt: RestoreReceipt = serde_json::from_value(receipt_value())?;
        assert_eq!(receipt.status, RestoreStatus::RestoredToNewRoot);
        assert_eq!(receipt.exact_action_hash.as_deref(), Some("sealed-action"));
        let report: RestoreReport = serde_json::from_value(json!({
            "component": "restore",
            "plan": plan_value(),
            "receipt": receipt_value(),
            "generated_at": wire_time(),
        }))?;
        assert_eq!(report.receipt.restore_plan_id, report.plan.restore_plan_id);
        Ok(())
    }

    /// Refusal case: an omitted effect-bearing member is refused at decode, so
    /// no historical form can silently become a completed effect record. Each
    /// case isolates its own member: the complete fixture decodes, and the
    /// refusal names the member that was removed.
    #[test]
    fn omitted_effect_bearing_safety_fields_are_refused_at_decode() {
        for field in [
            "surreal_source_endpoint",
            "surreal_source_storage_ref",
            "blob_payload_root",
        ] {
            assert_field_is_required::<BackupManifest>(manifest_value(), field);
        }
        for field in ["target_endpoint", "target_storage_ref", "exact_action_hash"] {
            assert_field_is_required::<RestorePlan>(plan_value(), field);
        }
        assert_field_is_required::<RestoreReceipt>(receipt_value(), "exact_action_hash");
    }

    /// Refusal case: an explicit `null` is the recorded absence, never a
    /// successful effect record — the value decodes as `None` so a consumer
    /// sees explicit unknown rather than a completed restore.
    #[test]
    fn explicit_null_effect_fields_decode_as_recorded_absence() -> Result<(), serde_json::Error> {
        let mut value = receipt_value();
        value["exact_action_hash"] = Value::Null;
        let receipt: RestoreReceipt = serde_json::from_value(value)?;
        assert!(receipt.exact_action_hash.is_none());
        assert_eq!(receipt.status, RestoreStatus::RestoredToNewRoot);

        let mut value = plan_value();
        value["exact_action_hash"] = Value::Null;
        let plan: RestorePlan = serde_json::from_value(value)?;
        assert!(plan.exact_action_hash.is_none());

        let mut value = manifest_value();
        value["blob_payload_root"] = Value::Null;
        let manifest: BackupManifest = serde_json::from_value(value)?;
        assert!(manifest.blob_payload_root.is_none());
        Ok(())
    }

    /// Refusal case: the pinned current schema version admits no other
    /// version, so there is no historical wire form whose omitted effect
    /// fields would need a versioned compatibility owner. The refusal is pinned
    /// to the version check itself, so it cannot be satisfied by an unrelated
    /// decode failure.
    #[test]
    fn no_other_schema_version_is_admitted_for_effect_bearing_manifests() {
        for version in ["0", "2", "", "1.0"] {
            let mut value = manifest_value();
            value["schema_version"] = Value::String(version.to_owned());
            let error = match serde_json::from_value::<BackupManifest>(value) {
                Ok(_) => panic!("a misselected schema_version `{version}` must be refused"),
                Err(error) => error,
            };
            let message = error.to_string();
            assert!(
                message.contains("unsupported backup manifest schema_version"),
                "the refusal must come from the schema_version pin, got: {message}"
            );
        }
    }

    /// The owner-written record round-trips through the owner's own
    /// encode/decode path unchanged: making the effect fields required
    /// accepted no new spelling and dropped none.
    #[test]
    fn owner_written_records_round_trip_unchanged() -> Result<(), serde_json::Error> {
        fn round_trip<T>(value: Value) -> Result<T, serde_json::Error>
        where
            T: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug + PartialEq,
        {
            let decoded: T = serde_json::from_value(value)?;
            let reencoded = serde_json::to_value(&decoded)?;
            assert_eq!(
                serde_json::from_value::<T>(reencoded)?,
                decoded,
                "the owner encode/decode path must be stable"
            );
            Ok(decoded)
        }

        let manifest: BackupManifest = round_trip(manifest_value())?;
        assert!(!manifest.dry_run);
        assert!(manifest.blob_payload_root.is_some());
        let plan: RestorePlan = round_trip(plan_value())?;
        assert_eq!(plan.exact_action_hash.as_deref(), Some("sealed-action"));
        let receipt: RestoreReceipt = round_trip(receipt_value())?;
        assert!(!receipt.dry_run);
        assert_eq!(receipt.exact_action_hash.as_deref(), Some("sealed-action"));
        Ok(())
    }
}
