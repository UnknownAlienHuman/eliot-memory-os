use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};
use time::OffsetDateTime;

pub const OPERATION_RUNTIME_CHECKPOINT_SCHEMA_VERSION: &str = "eliot-operation-runtime-v1";
pub const OPERATION_RESTART_WINDOW_SCHEMA_VERSION: &str = "eliot-operation-restart-window-v1";
pub const SEAL_STAGING_CHECKPOINT_SCHEMA_VERSION: &str = "eliot-seal-staging-checkpoint-v1";
pub const RUNTIME_INTEGRITY_REPORT_SCHEMA_VERSION: &str = "eliot-runtime-integrity-v1";
pub const RUNTIME_RECONCILE_DRY_RUN_SCHEMA_VERSION: &str = "eliot-runtime-reconcile-dry-run-v1";

/// Bounded refusal for a control-wal schema version this build does not own.
///
/// The durable control wal is reloaded verbatim on restart, so a record written
/// under an incompatible schema must fail closed at the decoder instead of
/// being read as a current generation, phase, dispatch or staging state. The
/// message is fixed and never echoes the received version back onto an
/// operator surface.
fn unsupported_schema_version<E>(expected: &str) -> E
where
    E: de::Error,
{
    E::custom(format!("unsupported schema version; expected {expected}"))
}

fn deserialize_operation_runtime_schema_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value == OPERATION_RUNTIME_CHECKPOINT_SCHEMA_VERSION {
        Ok(value)
    } else {
        Err(unsupported_schema_version(
            OPERATION_RUNTIME_CHECKPOINT_SCHEMA_VERSION,
        ))
    }
}

fn deserialize_restart_window_schema_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value == OPERATION_RESTART_WINDOW_SCHEMA_VERSION {
        Ok(value)
    } else {
        Err(unsupported_schema_version(
            OPERATION_RESTART_WINDOW_SCHEMA_VERSION,
        ))
    }
}

fn deserialize_seal_staging_schema_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value == SEAL_STAGING_CHECKPOINT_SCHEMA_VERSION {
        Ok(value)
    } else {
        Err(unsupported_schema_version(
            SEAL_STAGING_CHECKPOINT_SCHEMA_VERSION,
        ))
    }
}

/// Bounded refusal for a protected runtime identifier that decoded empty.
///
/// Operation, process and generation identity is what a checkpoint, a restart
/// window, a reap receipt and a supervision report are trusted by. An empty
/// string is not a weaker identifier, it is an absent one, so it must refuse
/// at the decoder instead of becoming a current key. Absence already refuses
/// through the missing-field path; this closes the spelled-out-empty spelling
/// of the same defect. The message is fixed and never echoes the received
/// value onto an operator surface.
fn empty_protected_identifier<E>(field: &'static str) -> E
where
    E: de::Error,
{
    E::custom(format!("empty protected identifier: {field}"))
}

fn deserialize_protected_string<'de, D>(
    deserializer: D,
    field: &'static str,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.is_empty() {
        return Err(empty_protected_identifier(field));
    }
    Ok(value)
}

fn deserialize_operation_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_string(deserializer, "operation_id")
}

fn deserialize_seal_attempt_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_string(deserializer, "seal_attempt_id")
}

fn deserialize_run_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_string(deserializer, "run_id")
}

fn deserialize_job_object_name<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_string(deserializer, "job_object_name")
}

fn deserialize_adapter_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_string(deserializer, "adapter_id")
}

fn deserialize_restart_window_key<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_string(deserializer, "key")
}

fn deserialize_descendants_at_root_exit_schema_version<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value == DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION {
        Ok(value)
    } else {
        Err(unsupported_schema_version(
            DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION,
        ))
    }
}

fn deserialize_runtime_integrity_report_schema_version<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value == RUNTIME_INTEGRITY_REPORT_SCHEMA_VERSION {
        Ok(value)
    } else {
        Err(unsupported_schema_version(
            RUNTIME_INTEGRITY_REPORT_SCHEMA_VERSION,
        ))
    }
}

fn deserialize_runtime_reconcile_dry_run_schema_version<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value == RUNTIME_RECONCILE_DRY_RUN_SCHEMA_VERSION {
        Ok(value)
    } else {
        Err(unsupported_schema_version(
            RUNTIME_RECONCILE_DRY_RUN_SCHEMA_VERSION,
        ))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationPhase {
    #[default]
    Prepared,
    Validating,
    Staging,
    AuthorityActivating,
    Published,
    DispatchStarting,
    AwaitingDispatchAck,
    AwaitingFirstOutput,
    Running,
    OutputDraining,
    Cancelling,
    Reaping,
    Reconciling,
    Completed,
    Failed,
    Abandoned,
}

impl OperationPhase {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Abandoned)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderDispatchState {
    #[default]
    NotStarted,
    Starting,
    Proven,
    AckUnknown,
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationCancellationState {
    #[default]
    NotRequested,
    Requested,
    Graceful,
    Forced,
    Reaped,
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationReconciliationState {
    #[default]
    NotRequired,
    Pending,
    Completed,
    Failed,
    NonReconcilableUnknown,
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterCircuitState {
    #[default]
    Closed,
    Open,
    HalfOpen,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRuntimeCheckpoint {
    #[serde(deserialize_with = "deserialize_operation_runtime_schema_version")]
    pub schema_version: String,
    #[serde(deserialize_with = "deserialize_operation_id")]
    pub operation_id: String,
    pub invocation_id: Option<String>,
    pub adapter_id: Option<String>,
    pub generation: u64,
    pub phase: OperationPhase,
    pub dispatch_state: ProviderDispatchState,
    pub cancellation_state: OperationCancellationState,
    pub reconciliation_state: OperationReconciliationState,
    pub root_pid: Option<u32>,
    pub root_process_start_ticks: Option<u64>,
    pub root_executable_sha256: Option<String>,
    pub job_object_name: Option<String>,
    pub active_process_count: u32,
    pub stdin_bytes: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub phase_started_at: OffsetDateTime,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub last_progress_at: OffsetDateTime,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub phase_deadline_at: OffsetDateTime,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub absolute_deadline_at: OffsetDateTime,
    pub restart_count: u32,
    pub restart_window_started_at: Option<String>,
    pub role_lease_id: Option<String>,
    pub role_lease_epoch: Option<u64>,
    pub runtime_contract_sha256: Option<String>,
    pub last_error_class: Option<String>,
    pub last_evidence_refs: Vec<String>,
}

impl OperationRuntimeCheckpoint {
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.phase.is_terminal()
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRestartWindow {
    #[serde(deserialize_with = "deserialize_restart_window_schema_version")]
    pub schema_version: String,
    #[serde(deserialize_with = "deserialize_restart_window_key")]
    pub key: String,
    pub restart_timestamps: Vec<String>,
    pub circuit_state: AdapterCircuitState,
    pub consecutive_failures: u32,
    // Each `default` below covers a last-observed timestamp, not a protected
    // identifier, version or discriminator: "this adapter has not succeeded
    // yet" is a real restart-window state that a window written before the
    // adapter ever succeeded has to express by leaving the key out. The bounds
    // this window exists to enforce are carried by the required `schema_version`,
    // `circuit_state`, `consecutive_failures` and `restart_timestamps` fields,
    // and `last_failure_class` beside them is likewise required, so a silent
    // default can never stand in for an absent bound.
    #[serde(default)]
    pub last_success_at: Option<String>,
    #[serde(default)]
    pub last_failure_at: Option<String>,
    pub last_failure_class: Option<String>,
    // Same reasoning as the timestamps above, and the absence is load-bearing in
    // both directions: an adapter that has never driven an operation to a
    // terminal phase has no such reference, and the supervising read maps a
    // window without one onto a `RuntimeAdapterHealth` that reports none.
    #[serde(default)]
    pub last_terminal_operation_ref: Option<String>,
    pub updated_at: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealStagingState {
    #[default]
    Staged,
    Activated,
    Published,
    Abandoned,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealStagingCheckpoint {
    #[serde(deserialize_with = "deserialize_seal_staging_schema_version")]
    pub schema_version: String,
    #[serde(deserialize_with = "deserialize_seal_attempt_id")]
    pub seal_attempt_id: String,
    #[serde(deserialize_with = "deserialize_run_id")]
    pub run_id: String,
    pub generation: u64,
    pub staging_root: String,
    pub manifest_sha256: String,
    pub state: SealStagingState,
    pub updated_at: String,
}

pub const DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION: &str = "eliot-descendants-at-root-exit-v1";
pub const MAX_DESCENDANTS_AT_ROOT_EXIT: usize = 64;
pub const MAX_DESCENDANT_IMAGE_PATH_CHARS: usize = 4096;
pub const MAX_DESCENDANT_DETAIL_CHARS: usize = 512;
pub const MAX_DESCENDANT_IMAGE_SHA256_CHARS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescendantFileIdentity {
    pub volume_serial_number: u32,
    pub file_index: u64,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct DescendantProcessSnapshot {
    pub pid: u32,
    pub start_ticks: u64,
    pub image_path: String,
    pub file_identity: DescendantFileIdentity,
    pub image_sha256: Option<String>,
}

/// Private wire mirror of [`DescendantProcessSnapshot`].
///
/// The snapshot's own identity and boundedness are decidable without knowing
/// which root process it was captured under, so the decoder builds the public
/// value through this mirror and then refuses it with the same owner check
/// `DescendantsAtRootExit::validate_snapshot` uses. A derived decoder here
/// would admit a zero `pid`, an empty `image_path` and a malformed
/// `image_sha256`, and a capture that cannot name a live descendant would still
/// decode as if it had.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DescendantProcessSnapshotWire {
    pid: u32,
    start_ticks: u64,
    image_path: String,
    file_identity: DescendantFileIdentity,
    image_sha256: Option<String>,
}

impl<'de> Deserialize<'de> for DescendantProcessSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = DescendantProcessSnapshotWire::deserialize(deserializer)?;
        let value = Self {
            pid: wire.pid,
            start_ticks: wire.start_ticks,
            image_path: wire.image_path,
            file_identity: wire.file_identity,
            image_sha256: wire.image_sha256,
        };
        // The recorded values are checked as recorded; nothing here re-derives a
        // substitute for a field the producer supplied.
        validate_descendant_identity(&value).map_err(de::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DescendantsCaptureErrorKind {
    Overflow,
    EnumerationFailed,
    AccessDenied,
    Ambiguous,
    Duplicate,
    InvalidPid,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct DescendantsAtRootExitCaptured {
    pub schema_version: String,
    pub root_pid: u32,
    pub root_exit_code: Option<i32>,
    pub capture_elapsed_ms: u64,
    pub descendants: Vec<DescendantProcessSnapshot>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct DescendantsAtRootExitFailed {
    pub schema_version: String,
    pub root_pid: Option<u32>,
    pub root_exit_code: Option<i32>,
    pub capture_elapsed_ms: u64,
    pub error_kind: DescendantsCaptureErrorKind,
    pub detail: String,
}

/// Private wire mirror of [`DescendantsAtRootExitCaptured`].
///
/// The captured variant is the record that claims the descendant tree was
/// enumerated at root exit, so its load-bearing invariants cannot be an opt-in
/// step: a derived decoder would accept `root_pid == 0` and an unsorted or
/// duplicated descendant list, and the receipt holding it would then be read as
/// a complete reap. The decoder therefore builds the public value through this
/// mirror and refuses it unless the owner's own captured-variant check passes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DescendantsAtRootExitCapturedWire {
    #[serde(deserialize_with = "deserialize_descendants_at_root_exit_schema_version")]
    schema_version: String,
    root_pid: u32,
    root_exit_code: Option<i32>,
    capture_elapsed_ms: u64,
    descendants: Vec<DescendantProcessSnapshot>,
}

impl<'de> Deserialize<'de> for DescendantsAtRootExitCaptured {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = DescendantsAtRootExitCapturedWire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            root_pid: wire.root_pid,
            root_exit_code: wire.root_exit_code,
            capture_elapsed_ms: wire.capture_elapsed_ms,
            descendants: wire.descendants,
        };
        validate_descendants_captured(&value).map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Private wire mirror of [`DescendantsAtRootExitFailed`].
///
/// A failure record is the evidence that enumeration did *not* complete, so it
/// is refused on the same terms as the captured variant: an unowned
/// `schema_version`, an oversized `detail` or a zero `root_pid` must not decode
/// into a value a caller would read as a decided capture outcome.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DescendantsAtRootExitFailedWire {
    #[serde(deserialize_with = "deserialize_descendants_at_root_exit_schema_version")]
    schema_version: String,
    root_pid: Option<u32>,
    root_exit_code: Option<i32>,
    capture_elapsed_ms: u64,
    error_kind: DescendantsCaptureErrorKind,
    detail: String,
}

impl<'de> Deserialize<'de> for DescendantsAtRootExitFailed {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = DescendantsAtRootExitFailedWire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            root_pid: wire.root_pid,
            root_exit_code: wire.root_exit_code,
            capture_elapsed_ms: wire.capture_elapsed_ms,
            error_kind: wire.error_kind,
            detail: wire.detail,
        };
        validate_descendants_failed(&value).map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Private wire mirror of [`DescendantsAtRootExit`].
///
/// Each variant above already refuses an invalid payload, so decoding through
/// this mirror and then running the owner's `validate()` keeps the enum
/// boundary fail-closed in its own right: "decoded but invalid" is not a
/// constructible state of this type on any ingress.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum DescendantsAtRootExitWire {
    Captured(DescendantsAtRootExitCaptured),
    Failed(DescendantsAtRootExitFailed),
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DescendantsAtRootExit {
    Captured(DescendantsAtRootExitCaptured),
    Failed(DescendantsAtRootExitFailed),
}

impl<'de> Deserialize<'de> for DescendantsAtRootExit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = match DescendantsAtRootExitWire::deserialize(deserializer)? {
            DescendantsAtRootExitWire::Captured(captured) => Self::Captured(captured),
            DescendantsAtRootExitWire::Failed(failed) => Self::Failed(failed),
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

impl DescendantsAtRootExit {
    pub fn captured(
        root_pid: u32,
        root_exit_code: Option<i32>,
        capture_elapsed_ms: u64,
        mut descendants: Vec<DescendantProcessSnapshot>,
    ) -> Result<Self, String> {
        if root_pid == 0 {
            return Err("root_pid must be non-zero".to_owned());
        }
        if descendants.len() > MAX_DESCENDANTS_AT_ROOT_EXIT {
            return Err(format!(
                "descendants overflow: {} > {}",
                descendants.len(),
                MAX_DESCENDANTS_AT_ROOT_EXIT
            ));
        }
        descendants.sort_by_key(|entry| entry.pid);
        for window in descendants.windows(2) {
            if window[0].pid == window[1].pid {
                return Err(format!("duplicate pid {}", window[0].pid));
            }
        }
        for entry in &descendants {
            Self::validate_snapshot(entry, root_pid)?;
        }
        Ok(Self::Captured(DescendantsAtRootExitCaptured {
            schema_version: DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION.to_owned(),
            root_pid,
            root_exit_code,
            capture_elapsed_ms,
            descendants,
        }))
    }

    pub fn failed(
        root_pid: Option<u32>,
        root_exit_code: Option<i32>,
        capture_elapsed_ms: u64,
        error_kind: DescendantsCaptureErrorKind,
        detail: impl Into<String>,
    ) -> Result<Self, String> {
        let detail = detail.into();
        if detail.chars().count() > MAX_DESCENDANT_DETAIL_CHARS {
            return Err(format!(
                "detail overflow: {} > {}",
                detail.chars().count(),
                MAX_DESCENDANT_DETAIL_CHARS
            ));
        }
        if let Some(pid) = root_pid
            && pid == 0
        {
            return Err("root_pid must be non-zero".to_owned());
        }
        Ok(Self::Failed(DescendantsAtRootExitFailed {
            schema_version: DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION.to_owned(),
            root_pid,
            root_exit_code,
            capture_elapsed_ms,
            error_kind,
            detail,
        }))
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Captured(captured) => validate_descendants_captured(captured),
            Self::Failed(failed) => validate_descendants_failed(failed),
        }
    }

    fn validate_snapshot(entry: &DescendantProcessSnapshot, root_pid: u32) -> Result<(), String> {
        validate_descendant_identity(entry)?;
        if entry.pid == root_pid {
            return Err(format!("descendant pid {} equals root pid", entry.pid));
        }
        Ok(())
    }

    #[must_use]
    pub fn is_captured(&self) -> bool {
        matches!(self, Self::Captured(_))
    }

    #[must_use]
    pub fn descendants(&self) -> Option<&[DescendantProcessSnapshot]> {
        match self {
            Self::Captured(captured) => Some(&captured.descendants),
            Self::Failed(_) => None,
        }
    }
}

/// The single owner of the captured-variant invariants.
///
/// `DescendantsAtRootExit::validate`, the public constructor and the captured
/// decoder all route through this one function, so no ingress can hold a
/// weaker variant of the rule: a non-zero `root_pid`, a bounded, sorted and
/// duplicate-free descendant list whose entries all satisfy
/// [`validate_descendant_identity`] and do not name the root itself.
fn validate_descendants_captured(captured: &DescendantsAtRootExitCaptured) -> Result<(), String> {
    if captured.schema_version != DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION {
        return Err(format!(
            "invalid schema_version {}",
            captured.schema_version
        ));
    }
    if captured.root_pid == 0 {
        return Err("root_pid must be non-zero".to_owned());
    }
    if captured.descendants.len() > MAX_DESCENDANTS_AT_ROOT_EXIT {
        return Err("descendants overflow".to_owned());
    }
    let mut sorted = captured.descendants.clone();
    sorted.sort_by_key(|entry| entry.pid);
    if sorted != captured.descendants {
        return Err("descendants must be sorted by pid".to_owned());
    }
    for entry in &captured.descendants {
        DescendantsAtRootExit::validate_snapshot(entry, captured.root_pid)?;
    }
    for window in captured.descendants.windows(2) {
        if window[0].pid == window[1].pid {
            return Err(format!("duplicate pid {}", window[0].pid));
        }
    }
    Ok(())
}

/// The single owner of the failed-variant invariants.
fn validate_descendants_failed(failed: &DescendantsAtRootExitFailed) -> Result<(), String> {
    if failed.schema_version != DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION {
        return Err(format!("invalid schema_version {}", failed.schema_version));
    }
    if failed.detail.chars().count() > MAX_DESCENDANT_DETAIL_CHARS {
        return Err("detail overflow".to_owned());
    }
    if let Some(pid) = failed.root_pid
        && pid == 0
    {
        return Err("root_pid must be non-zero".to_owned());
    }
    Ok(())
}

/// The root-independent half of a descendant snapshot's invariants.
///
/// Whether a snapshot's `pid` also equals the root pid is only decidable inside
/// the captured variant, but its own identity and boundedness are decidable on
/// its own terms and are therefore refused at its own decoder as well as by
/// [`DescendantsAtRootExit::validate_snapshot`].
///
/// The recorded `image_sha256` is checked as recorded: when present it must be a
/// full lowercase 64-character hex digest. No digest is recomputed here, because
/// the bytes that were hashed are not part of this record and re-deriving one
/// would validate a substitute for the producer's evidence rather than the
/// evidence itself.
fn validate_descendant_identity(entry: &DescendantProcessSnapshot) -> Result<(), String> {
    if entry.pid == 0 {
        return Err("pid must be non-zero".to_owned());
    }
    if entry.image_path.chars().count() > MAX_DESCENDANT_IMAGE_PATH_CHARS {
        return Err(format!(
            "image_path overflow: {} > {}",
            entry.image_path.chars().count(),
            MAX_DESCENDANT_IMAGE_PATH_CHARS
        ));
    }
    if entry.image_path.is_empty() {
        return Err("image_path must be non-empty".to_owned());
    }
    if let Some(sha) = &entry.image_sha256 {
        if sha.chars().count() > MAX_DESCENDANT_IMAGE_SHA256_CHARS {
            return Err("image_sha256 overflow".to_owned());
        }
        if sha.is_empty() {
            return Err("image_sha256 must be non-empty".to_owned());
        }
        if !is_lowercase_sha256_hex(sha) {
            return Err("image_sha256 must be a lowercase 64-character hex digest".to_owned());
        }
    }
    Ok(())
}

/// True when `value` is exactly 64 lowercase hexadecimal characters.
fn is_lowercase_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProcessReapReceipt {
    #[serde(deserialize_with = "deserialize_operation_id")]
    pub operation_id: String,
    pub generation: u64,
    #[serde(deserialize_with = "deserialize_job_object_name")]
    pub job_object_name: String,
    pub root_pid: Option<u32>,
    pub process_count_before: u32,
    pub process_count_after: u32,
    pub graceful_attempted: bool,
    pub forced_termination: bool,
    pub stdout_closed: bool,
    pub stderr_closed: bool,
    pub all_tasks_joined: bool,
    pub elapsed_ms: u64,
    pub terminal_error_codes: Vec<u32>,
    /// The descendant observation is the evidence that decides whether the
    /// process tree was actually gone at root exit. This receipt is a durable
    /// journal field read back with a plain `serde_json::from_slice`, so the
    /// nested record is routed through its own validating decoder rather than
    /// letting the derived struct build an unvalidated one: a malformed capture
    /// can no longer reach a caller at all, let alone as trusted evidence.
    #[serde(deserialize_with = "deserialize_descendants_at_root_exit")]
    pub descendants_at_root_exit: DescendantsAtRootExit,
}

fn deserialize_descendants_at_root_exit<'de, D>(
    deserializer: D,
) -> Result<DescendantsAtRootExit, D::Error>
where
    D: Deserializer<'de>,
{
    DescendantsAtRootExit::deserialize(deserializer)
}

impl ProcessReapReceipt {
    /// Whether this receipt proves the process tree was completely reaped.
    ///
    /// Fails closed on the descendant evidence. The counters, stream and task
    /// flags say nothing about descendants that outlived the root process, so a
    /// capture that violates its own recorded invariants — a zero `root_pid`, an
    /// unsorted or duplicated descendant list, an empty `image_path` — cannot be
    /// counted as a complete reap. Such a record is refused outright by the
    /// decoder, so reaching this predicate with one means the value was
    /// assembled in memory; the fields are public, and the invariant is
    /// therefore re-checked here rather than trusted from whichever ingress built
    /// it.
    ///
    /// A well-formed `Failed` capture is *not* treated as untrusted here: it is
    /// the producer's honest record that enumeration did not finish before
    /// bounded cleanup, and the process-tree counters remain the cleanup
    /// evidence for that case. Requiring a `Captured` record would contradict the
    /// bounded-reaping guarantee that an incomplete descendant capture must not
    /// block a reap whose counters, streams and tasks all closed.
    #[must_use]
    pub fn proves_complete_reap(&self) -> bool {
        if self.descendants_at_root_exit.validate().is_err() {
            return false;
        }
        self.process_count_after == 0
            && self.stdout_closed
            && self.stderr_closed
            && self.all_tasks_joined
            && (self.forced_termination || self.terminal_error_codes.is_empty())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the runtime health wire contract exposes independent readiness dimensions"
)]
pub struct RuntimeCoreHealth {
    pub ready: bool,
    pub ipc_ready: bool,
    pub db_ready: bool,
    pub writer_ready: bool,
    pub read_service_ready: bool,
    pub service_generation: Option<String>,
    pub executable_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAdapterHealth {
    #[serde(deserialize_with = "deserialize_adapter_id")]
    pub adapter_id: String,
    pub installed: bool,
    pub authenticated: bool,
    pub ready: bool,
    pub circuit_state: AdapterCircuitState,
    pub active_operations: u32,
    pub queued_operations: u32,
    pub restart_count_window: u32,
    pub last_success_at: Option<String>,
    pub last_failure_at: Option<String>,
    pub last_failure_class: Option<String>,
    // Added after the report had already shipped, so an older artifact on disk
    // omits this key entirely. Absence is the meaningful state — this adapter has
    // not yet produced a terminal operation to attribute — and the neighbouring
    // `last_*` observation fields in the same struct are required rather than
    // defaulted. A silent `None` here therefore reports an honest absence, and
    // it cannot mask an authority, version or discriminator: this struct carries
    // no such field, so there is nothing protected to default over.
    #[serde(default)]
    pub last_terminal_operation_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeOperationDetail {
    #[serde(deserialize_with = "deserialize_operation_id")]
    pub operation_id: String,
    pub generation: u64,
    pub phase: OperationPhase,
    pub last_progress_at: String,
    pub phase_deadline_at: String,
    pub root_pid: Option<u32>,
    pub active_process_count: u32,
    pub stdin_state: String,
    pub stdout_state: String,
    pub stderr_state: String,
    pub cancellation_state: OperationCancellationState,
    pub reconciliation_state: OperationReconciliationState,
    pub role_lease_id: Option<String>,
    pub role_lease_epoch: Option<u64>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeOperationHealth {
    pub active: u32,
    pub stuck: u32,
    pub awaiting_reconciliation: u32,
    pub cleanup_pending: u32,
    pub orphan_processes: u32,
    pub oldest_last_progress_at: Option<String>,
    pub details: Vec<RuntimeOperationDetail>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAuthorityIntegrity {
    pub active_sessions: u32,
    pub active_role_leases: u32,
    pub pending_role_leases: u32,
    pub orphaned_role_leases: u32,
    pub revoked_role_leases: u32,
    pub stale_epoch_results: u32,
    pub partial_seals: u32,
    pub published_plans_without_authority: u32,
    pub published_seal_runtime_drift: u32,
    pub authority_without_published_plan: u32,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIntegrityHealth {
    pub clean: bool,
    pub expected_governor_sha256: Option<String>,
    pub observed_governor_sha256: Option<String>,
    pub locked_active_binary: Option<String>,
    pub process_orphans: u32,
    pub incomplete_staging_roots: u32,
    pub quarantine_records: u32,
    pub last_startup_recovery_ref: Option<String>,
    pub last_watchdog_action_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeOverallStatus {
    Ready,
    Degraded,
    IntegrityFailed,
    NotReady,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSupervisionReport {
    // The report is the durable `reports/runtime-supervision/latest.json`
    // artifact and every downstream read of its `overall`, `reason`,
    // `provider_dispatch_safe` and `integrity_errors` acts on this generation's
    // readiness verdict. The constant is minted by this crate precisely so the
    // decoder can refuse any other generation rather than let one be read as a
    // current integrity verdict.
    #[serde(deserialize_with = "deserialize_runtime_integrity_report_schema_version")]
    pub schema_version: String,
    pub generated_at: String,
    pub core: RuntimeCoreHealth,
    pub adapters: Vec<RuntimeAdapterHealth>,
    pub operations: RuntimeOperationHealth,
    pub authority_integrity: RuntimeAuthorityIntegrity,
    pub runtime_integrity: RuntimeIntegrityHealth,
    pub overall: RuntimeOverallStatus,
    pub reason: String,
    pub provider_dispatch_safe: bool,
    pub integrity_errors: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReconcileDecision {
    #[serde(deserialize_with = "deserialize_operation_id")]
    pub operation_id: String,
    pub generation: u64,
    pub decision: String,
    pub mutates: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReconcileDryRun {
    // The dry run publishes the reconcile decisions an operator would apply. A
    // decision list minted under another generation names a different decision
    // vocabulary, so it must be refused at the decoder instead of being read as
    // this build's proposed reconciliation plan.
    #[serde(deserialize_with = "deserialize_runtime_reconcile_dry_run_schema_version")]
    pub schema_version: String,
    pub generated_at: String,
    pub dry_run: bool,
    pub decisions: Vec<RuntimeReconcileDecision>,
    pub provider_calls: u32,
    pub writes: u32,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        DescendantFileIdentity, DescendantProcessSnapshot, DescendantsAtRootExit,
        DescendantsAtRootExitCaptured, DescendantsCaptureErrorKind,
        DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION, MAX_DESCENDANT_DETAIL_CHARS,
        MAX_DESCENDANT_IMAGE_PATH_CHARS, MAX_DESCENDANTS_AT_ROOT_EXIT, ProcessReapReceipt,
    };

    fn empty_captured(root_pid: u32) -> DescendantsAtRootExit {
        DescendantsAtRootExit::captured(root_pid, Some(0), 10, Vec::new()).unwrap()
    }

    fn descendant(pid: u32, _root_pid: u32) -> DescendantProcessSnapshot {
        DescendantProcessSnapshot {
            pid,
            start_ticks: 1_000 + u64::from(pid),
            image_path: format!("C:\\Windows\\System32\\descendant-{pid}.exe"),
            file_identity: DescendantFileIdentity {
                volume_serial_number: 0x1234,
                file_index: u64::from(pid) * 10,
            },
            image_sha256: Some(format!("{pid:064x}")),
        }
    }

    #[test]
    fn runtime_supervision_reap_receipt_requires_zero_members_and_joined_pipes() {
        let mut receipt = ProcessReapReceipt {
            operation_id: "op-1".to_owned(),
            generation: 1,
            job_object_name: "Eliot-op-1-g1".to_owned(),
            root_pid: Some(10),
            process_count_before: 2,
            process_count_after: 1,
            graceful_attempted: false,
            forced_termination: true,
            stdout_closed: true,
            stderr_closed: true,
            all_tasks_joined: true,
            elapsed_ms: 20,
            terminal_error_codes: Vec::new(),
            descendants_at_root_exit: empty_captured(10),
        };
        assert!(!receipt.proves_complete_reap());
        receipt.process_count_after = 0;
        assert!(receipt.proves_complete_reap());
        receipt.terminal_error_codes.push(109);
        assert!(receipt.proves_complete_reap());
        receipt.forced_termination = false;
        assert!(!receipt.proves_complete_reap());
    }

    #[test]
    fn descendants_captured_rejects_pid_zero_and_root_pid() {
        assert!(DescendantsAtRootExit::captured(10, None, 0, vec![descendant(0, 10)]).is_err());
        assert!(DescendantsAtRootExit::captured(10, None, 0, vec![descendant(10, 10)]).is_err());
    }

    #[test]
    fn descendants_captured_enforces_sort_and_dedup() {
        let first = descendant(20, 10);
        let second = descendant(21, 10);
        let out_of_order =
            DescendantsAtRootExit::captured(10, None, 5, vec![second.clone(), first.clone()]);
        assert!(out_of_order.is_ok());
        if let DescendantsAtRootExit::Captured(captured) = out_of_order.unwrap() {
            assert_eq!(captured.descendants[0].pid, 20);
            assert_eq!(captured.descendants[1].pid, 21);
        } else {
            panic!("expected captured");
        }
        let duplicate =
            DescendantsAtRootExit::captured(10, None, 5, vec![first.clone(), first.clone()]);
        assert!(duplicate.is_err());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn descendants_captured_rejects_overflow_and_path_bounds() {
        let many = (1..=MAX_DESCENDANTS_AT_ROOT_EXIT + 1)
            .map(|pid| descendant(u32::try_from(pid).unwrap() + 100, 10))
            .collect::<Vec<_>>();
        assert!(DescendantsAtRootExit::captured(10, None, 0, many).is_err());
        let mut long = descendant(30, 10);
        long.image_path = "a".repeat(MAX_DESCENDANT_IMAGE_PATH_CHARS + 1);
        assert!(DescendantsAtRootExit::captured(10, None, 0, vec![long]).is_err());
    }

    #[test]
    fn descendants_failed_rejects_detail_overflow() {
        let long = "x".repeat(MAX_DESCENDANT_DETAIL_CHARS + 1);
        assert!(
            DescendantsAtRootExit::failed(
                Some(10),
                None,
                0,
                DescendantsCaptureErrorKind::Overflow,
                long
            )
            .is_err()
        );
    }

    #[test]
    fn descendants_serialization_round_trips_and_validates_bounds() {
        let captured =
            DescendantsAtRootExit::captured(10, Some(0), 5, vec![descendant(20, 10)]).unwrap();
        let json = serde_json::to_string(&captured).unwrap();
        let decoded: DescendantsAtRootExit = serde_json::from_str(&json).unwrap();
        assert!(decoded.validate().is_ok());
        assert_eq!(captured, decoded);
        let receipt = ProcessReapReceipt {
            operation_id: "op-2".to_owned(),
            generation: 1,
            job_object_name: "Eliot-op-2-g1".to_owned(),
            root_pid: Some(10),
            process_count_before: 2,
            process_count_after: 0,
            graceful_attempted: false,
            forced_termination: true,
            stdout_closed: true,
            stderr_closed: true,
            all_tasks_joined: true,
            elapsed_ms: 20,
            terminal_error_codes: Vec::new(),
            descendants_at_root_exit: captured,
        };
        let receipt_json = serde_json::to_string(&receipt).unwrap();
        let decoded_receipt: ProcessReapReceipt = serde_json::from_str(&receipt_json).unwrap();
        assert!(decoded_receipt.descendants_at_root_exit.validate().is_ok());
    }

    #[test]
    fn old_receipt_without_descendants_fails_to_deserialize() {
        let old = serde_json::json!({
            "operation_id": "op-1",
            "generation": 1,
            "job_object_name": "Eliot-op-1-g1",
            "root_pid": 10,
            "process_count_before": 1,
            "process_count_after": 0,
            "graceful_attempted": false,
            "forced_termination": true,
            "stdout_closed": true,
            "stderr_closed": true,
            "all_tasks_joined": true,
            "elapsed_ms": 20,
            "terminal_error_codes": []
        });
        let decoded: Result<ProcessReapReceipt, _> = serde_json::from_value(old);
        assert!(decoded.is_err());
    }

    #[test]
    fn failed_snapshot_is_not_authoritative_empty() {
        let failed = DescendantsAtRootExit::failed(
            Some(10),
            Some(1),
            5,
            DescendantsCaptureErrorKind::AccessDenied,
            "access denied",
        )
        .unwrap();
        assert!(!failed.is_captured());
        assert!(failed.descendants().is_none());
        assert!(failed.validate().is_ok());
        let captured_empty = empty_captured(10);
        assert!(captured_empty.is_captured());
        assert_eq!(captured_empty.descendants().unwrap().len(), 0);
    }

    #[test]
    fn schema_version_must_match_constant() {
        let mut captured = DescendantsAtRootExit::captured(10, None, 0, Vec::new()).unwrap();
        if let DescendantsAtRootExit::Captured(ref mut inner) = captured {
            inner.schema_version = "wrong".to_owned();
        }
        assert!(captured.validate().is_err());
    }

    /// Positive case for AUD1 (#931): a well-formed capture carrying the pinned
    /// `schema_version` and a valid, sorted descendant list still decodes, and the
    /// receipt built from it still proves a complete reap. The fixture is the
    /// audit's own counterexample with the one illegal value repaired
    /// (`root_pid: 0` becomes a real root pid and one live descendant is added),
    /// so the refusal below differs from this only in the field under test.
    #[test]
    fn valid_capture_decodes_and_still_proves_complete_reap() {
        let json = r#"{
            "operation_id": "op-1",
            "generation": 1,
            "job_object_name": "job-1",
            "root_pid": 10,
            "process_count_before": 1,
            "process_count_after": 0,
            "graceful_attempted": true,
            "forced_termination": true,
            "stdout_closed": true,
            "stderr_closed": true,
            "all_tasks_joined": true,
            "elapsed_ms": 1,
            "terminal_error_codes": [],
            "descendants_at_root_exit": {
                "kind": "captured",
                "schema_version": "eliot-descendants-at-root-exit-v1",
                "root_pid": 10,
                "root_exit_code": 0,
                "capture_elapsed_ms": 1,
                "descendants": [
                    {
                        "pid": 20,
                        "start_ticks": 1000,
                        "image_path": "C:\\Windows\\System32\\descendant-20.exe",
                        "file_identity": { "volume_serial_number": 4660, "file_index": 200 },
                        "image_sha256": "0000000000000000000000000000000000000000000000000000000000000014"
                    }
                ]
            }
        }"#;
        let receipt: ProcessReapReceipt = serde_json::from_str(json).unwrap();
        assert!(receipt.descendants_at_root_exit.validate().is_ok());
        assert!(receipt.descendants_at_root_exit.is_captured());
        assert_eq!(
            receipt
                .descendants_at_root_exit
                .descendants()
                .map(<[DescendantProcessSnapshot]>::len),
            Some(1)
        );
        assert!(receipt.proves_complete_reap());
    }

    /// Refusal case for AUD1 (#931): the audit's exact counterexample JSON, whose
    /// captured `descendants_at_root_exit` names `root_pid: 0`. A capture cannot
    /// have observed a tree at the exit of a process that does not exist, so the
    /// record must be refused at the decode boundary rather than decoded and then
    /// counted as a complete reap.
    #[test]
    fn audit_counterexample_zero_root_pid_capture_is_refused_and_never_proves_complete_reap() {
        let json = r#"{
            "operation_id": "op-1",
            "generation": 1,
            "job_object_name": "job-1",
            "root_pid": null,
            "process_count_before": 1,
            "process_count_after": 0,
            "graceful_attempted": true,
            "forced_termination": true,
            "stdout_closed": true,
            "stderr_closed": true,
            "all_tasks_joined": true,
            "elapsed_ms": 1,
            "terminal_error_codes": [],
            "descendants_at_root_exit": {
                "kind": "captured",
                "schema_version": "eliot-descendants-at-root-exit-v1",
                "root_pid": 0,
                "root_exit_code": 0,
                "capture_elapsed_ms": 1,
                "descendants": []
            }
        }"#;
        // Refused at the actual decoder: every counter and stream flag in this
        // document is clean, so nothing but the descendant invariant can reject it.
        let decoded: Result<ProcessReapReceipt, _> = serde_json::from_str(json);
        assert!(
            decoded.is_err(),
            "capture with root_pid 0 must not decode into a trusted receipt"
        );

        // The same evidence assembled in memory (the fields are public, so no
        // decoder stands between a producer and this predicate) must not be
        // promoted to a complete reap either.
        let assembled = ProcessReapReceipt {
            operation_id: "op-1".to_owned(),
            generation: 1,
            job_object_name: "job-1".to_owned(),
            root_pid: None,
            process_count_before: 1,
            process_count_after: 0,
            graceful_attempted: true,
            forced_termination: true,
            stdout_closed: true,
            stderr_closed: true,
            all_tasks_joined: true,
            elapsed_ms: 1,
            terminal_error_codes: Vec::new(),
            descendants_at_root_exit: DescendantsAtRootExit::Captured(
                DescendantsAtRootExitCaptured {
                    schema_version: DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION.to_owned(),
                    root_pid: 0,
                    root_exit_code: Some(0),
                    capture_elapsed_ms: 1,
                    descendants: Vec::new(),
                },
            ),
        };
        assert!(!assembled.proves_complete_reap());
    }
}
