//! WASM parent P03 drive (issue #1955, I14.19).
//!
//! The dedicated executable consumer: from owner-published dispatch
//! material this process (the installed image, acting as the P03 parent)
//! derives its in-child authority, issues the one-shot permit for the
//! `--guest-exec` intent, stages/starts/reaps the reaped child through the
//! real [`WindowsProcessExecutor`](eliot_process_executor::WindowsProcessExecutor),
//! and returns the canonical guest output. No stub ports, no
//! request-selected authority, no fake P-07 permission: the permit is
//! issued by [`WasmDispatchAuthority`](crate::dispatch_authority::WasmDispatchAuthority)
//! funded exclusively by the validated dispatch grant, and the executor
//! re-hashes the installed image before any start.
//!
//! THE CANONICAL WASM INTENT RULE (the owner-side publisher runs the
//! identical forward computation; every field is fixed before any join
//! digest exists, so the derivation is acyclic):
//!
//! ```text
//! operation_id  = the admitted claim operation identity
//! process_tree  = the admitted claim identity (distinct type, one value)
//! job_id        = the admitted operation identity (distinct type, one value)
//! image_id      = "wasm-host-image-" + short(owner-measured host digest)
//! session_id    = the admitted claim identity (distinct type, one value)
//! generation    = the claiming generation
//! executable    = the resolved installed image path (current_exe,
//!                 re-hashed against the owner-measured digest)
//! argv          = the exact --guest-exec set: `--profile` plus the
//!                 owner-selected composition first, then colocated
//!                 artifact/input paths, their re-hashed digests, and the
//!                 material ceilings
//! working_dir   = the executable parent directory
//! environment   = empty secret-free projection
//! limits        = wall/fuel/memory/output ceilings from the material;
//!                 exactly one descendant (the reaped child itself — the
//!                 guest runs in-process and spawns no OS processes)
//! ```
//!
//! Nothing comes from CLI transport facts: identities and ceilings come
//! from the validated material, paths from the OS loader layout. The drive
//! ends at the canonical response (guest output bytes plus their digest and
//! the child-observed metering); seating `IsolatedChildEngine::invoke`
//! additionally needs Governor-issued invocation receipts, which stay with
//! the invocation owner lane.
//!
//! Failure discipline: stage-taxonomy [`DriveError`] codes only. No paths,
//! bytes, or digests echoed.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use eliot_process::{
    EnvironmentInheritance, EnvironmentProjection, EvidenceSinkError, Generation, ImageId, JobId,
    OperationId, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError, ProcessIntent,
    ProcessLifecycle, ProcessRequest, ProcessTreeId, ResourceLimits, SessionId,
};
use eliot_process_executor::{WindowsProcessExecutor, wasm_p03_adapter::WasmP03ProcessAdapter};
use eliot_wasm_runtime::{P03ProcessPort, ProcessBinding, Sha256Digest};

use crate::dispatch_authority::{DispatchAuthorityError, WasmDispatchAuthority};
use crate::dispatch_material::{MaterialError, ValidatedDispatchMaterial, read_dispatch_material};
use crate::guest_exec::parse_metering_line;
use crate::installed_binary::{
    InstalledBinaryError, WasmHostBinaryBinding, resolve_installed_binary,
};

/// Exact `--guest-exec` argv assembled for the reaped child. Spellings
/// match the CLI contract; values are material-proven, never ambient.
pub const GUEST_EXEC_ARGV0_HINT: &str = "--guest-exec";

/// Fail-closed drive errors: pipeline stage plus stable detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DriveError {
    /// No dispatch material was delivered.
    NoMaterial,
    /// Material validation failed.
    Material(MaterialError),
    /// Installed-image resolution failed.
    Resolve(InstalledBinaryError),
    /// Dispatch authority derivation or issuance failed.
    Authority(DispatchAuthorityError),
    /// Intent derivation failed.
    Intent {
        /// Stable field name.
        field: &'static str,
    },
    /// Staging, start, reap, or capture failed.
    Execution {
        /// Stable stage name.
        stage: &'static str,
    },
}

impl std::fmt::Display for DriveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMaterial => formatter.write_str("DISPATCH_DRIVE_NO_MATERIAL"),
            Self::Material(error) => write!(formatter, "{error}"),
            Self::Resolve(error) => write!(formatter, "{error}"),
            Self::Authority(error) => write!(formatter, "{error}"),
            Self::Intent { field } => write!(formatter, "DISPATCH_DRIVE_INTENT:{field}"),
            Self::Execution { stage } => write!(formatter, "DISPATCH_DRIVE_EXECUTION:{stage}"),
        }
    }
}

impl std::error::Error for DriveError {}

/// Canonical dispatch response: the guest output bytes plus the
/// tamper-evident facts binding them to the admitted operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchDriveResponse {
    /// Admitted operation identity.
    pub operation_id: String,
    /// Pinned component identity.
    pub component_id: String,
    /// Proven artifact digest (hex).
    pub artifact_digest: String,
    /// Proven input digest (hex).
    pub input_digest: String,
    /// Owner-measured host digest the child image resolved against (hex).
    pub host_artifact_digest: String,
    /// SHA-256 of the exact guest output bytes (hex).
    pub output_digest: String,
    /// Exact guest output bytes observed through P03 capture.
    pub output: Vec<u8>,
    /// Child-observed fuel consumed.
    pub fuel_consumed: u64,
    /// Child-observed peak memory bytes.
    pub peak_memory_bytes: u64,
    /// Child-observed table elements.
    pub table_elements: u64,
    /// Child-observed epoch ticks.
    pub epoch_ticks: u64,
}

/// Bounded production evidence sink: retains evidence up to the cap, then
/// fails closed (never drops retained evidence silently).
struct BoundedDriveSink {
    retained: Mutex<Vec<ProcessEvidence>>,
}

impl BoundedDriveSink {
    const CAP: usize = 1024;

    fn new() -> Self {
        Self {
            retained: Mutex::new(Vec::new()),
        }
    }
}

impl ProcessEvidenceSink for BoundedDriveSink {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
        let mut guard = self.retained.lock().map_err(|_| EvidenceSinkError {
            message: "drive sink lock poisoned".to_owned(),
        })?;
        if guard.len() >= Self::CAP {
            return Err(EvidenceSinkError {
                message: "drive sink at capacity".to_owned(),
            });
        }
        guard.push(evidence);
        Ok(())
    }
}

/// Resolves the installed child image: this process's own executable path
/// re-hashed against the owner-measured digest from the material. This
/// closes the #1955 loop in the real chain without any CLI descriptor file.
fn resolve_drive_image(
    material: &ValidatedDispatchMaterial,
) -> Result<(PathBuf, Sha256Digest), DriveError> {
    let executable =
        std::env::current_exe().map_err(|_| DriveError::Execution { stage: "locator" })?;
    let binding = WasmHostBinaryBinding::new(executable, material.host_artifact_digest.clone())
        .map_err(DriveError::Resolve)?;
    let installed = resolve_installed_binary(&binding).map_err(DriveError::Resolve)?;
    Ok((installed.path().to_path_buf(), installed.digest().clone()))
}

/// Derives the `--guest-exec` argv for the reaped child from proven
/// material: the owner-selected composition profile first (the child
/// composition must parse — a profile-less child exits before any guest),
/// then colocated files plus their re-hashed digests plus ceilings.
fn guest_exec_argv(
    material: &ValidatedDispatchMaterial,
    directory: &Path,
) -> Result<Vec<String>, DriveError> {
    let artifact = directory.join(crate::dispatch_material::WASM_HOST_GUEST_ARTIFACT_FILE_NAME);
    let input = directory.join(crate::dispatch_material::WASM_HOST_GUEST_INPUT_FILE_NAME);
    let artifact_text = artifact.to_str().ok_or(DriveError::Intent {
        field: "artifact-path",
    })?;
    let input_text = input.to_str().ok_or(DriveError::Intent {
        field: "input-path",
    })?;
    let ceilings = &material.ceilings;
    let argv = vec![
        "--profile".to_owned(),
        material.profile.as_str().to_owned(),
        GUEST_EXEC_ARGV0_HINT.to_owned(),
        "--guest-exec-artifact".to_owned(),
        artifact_text.to_owned(),
        "--guest-exec-input".to_owned(),
        input_text.to_owned(),
        "--guest-exec-artifact-digest".to_owned(),
        ceilings.artifact_digest.as_str().to_owned(),
        "--guest-exec-max-output".to_owned(),
        ceilings.max_output_bytes.to_string(),
        "--guest-exec-max-fuel".to_owned(),
        ceilings.max_fuel.to_string(),
        "--guest-exec-max-memory".to_owned(),
        ceilings.max_memory_bytes.to_string(),
        "--guest-exec-wall-ms".to_owned(),
        ceilings.wall_deadline_ms.to_string(),
        "--guest-exec-epoch-ticks".to_owned(),
        ceilings.epoch_deadline_ticks.to_string(),
    ];
    Ok(argv)
}

/// Derives the exact immutable `ProcessIntent` for the reaped child per the
/// canonical rule above. Every identity is admitted material; the two paths
/// are the OS loader layout.
fn derive_drive_intent(
    material: &ValidatedDispatchMaterial,
    executable: &Path,
    host_digest: &Sha256Digest,
    working_directory: &Path,
) -> Result<ProcessIntent, DriveError> {
    let intent_field = |field: &'static str| DriveError::Intent { field };
    let executable_text = executable
        .to_str()
        .ok_or_else(|| intent_field("executable"))?;
    let working_text = working_directory
        .to_str()
        .ok_or_else(|| intent_field("working-directory"))?;
    let short = host_digest
        .as_str()
        .get(..16)
        .ok_or_else(|| intent_field("host-digest"))?;
    let environment = EnvironmentProjection::new(
        std::collections::BTreeMap::new(),
        Vec::new(),
        EnvironmentInheritance::None,
    )
    .map_err(|_| intent_field("environment"))?;
    let ceilings = &material.ceilings;
    let limits = ResourceLimits::new(
        ceilings.wall_deadline_ms,
        None,
        Some(ceilings.max_memory_bytes),
        ceilings.max_output_bytes,
        ceilings.max_output_bytes,
        1,
    )
    .map_err(|_| intent_field("limits"))?;
    let generation =
        Generation::new(material.generation).map_err(|_| intent_field("generation"))?;
    let directory = executable
        .parent()
        .ok_or_else(|| intent_field("executable-dir"))?;
    let argv = guest_exec_argv(material, directory)?;
    ProcessIntent::new(
        OperationId::new(material.operation_id.clone()).map_err(|_| intent_field("operation"))?,
        ProcessTreeId::new(material.claim_id.clone()).map_err(|_| intent_field("tree"))?,
        JobId::new(material.operation_id.clone()).map_err(|_| intent_field("job"))?,
        ImageId::new(format!("wasm-host-image-{short}")).map_err(|_| intent_field("image"))?,
        SessionId::new(material.claim_id.clone()).map_err(|_| intent_field("session"))?,
        generation,
        executable_text.to_owned(),
        host_digest.as_str().to_owned(),
        argv,
        working_text.to_owned(),
        environment,
        limits,
    )
    .map_err(|_| intent_field("intent"))
}

/// Issues the one-shot permit for the derived intent from the validated
/// grant. Freshness is file-derived through the grant window.
fn issue_drive_permit(
    material: &ValidatedDispatchMaterial,
    authority: &WasmDispatchAuthority,
    intent: &ProcessIntent,
    now_ms: u64,
) -> Result<ProcessRequest, DriveError> {
    authority
        .issue(intent, &material.grant, &material.launch_nonce, now_ms)
        .map_err(DriveError::Authority)
}

/// Current Unix time in milliseconds for issuance freshness.
fn now_unix_ms() -> Result<u64, DriveError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .map_err(|_| DriveError::Execution { stage: "clock" })
}

/// Drives one admitted dispatch to the canonical response: resolve →
/// derive authority → derive intent → issue → stage → start → reap →
/// capture → metering. The child execution is real; every boundary fails
/// closed with unknown outcome preserved (never a fabricated byte).
pub fn drive_dispatch() -> Result<DispatchDriveResponse, DriveError> {
    let material = read_dispatch_material()
        .map_err(DriveError::Material)?
        .ok_or(DriveError::NoMaterial)?;
    drive_material(&material)
}

/// Drives one already-validated material to the canonical response.
/// Separated so the validation boundary stays independently testable.
fn drive_material(
    material: &ValidatedDispatchMaterial,
) -> Result<DispatchDriveResponse, DriveError> {
    let (executable, host_digest) = resolve_drive_image(material)?;
    let working_directory = executable
        .parent()
        .ok_or(DriveError::Intent {
            field: "working-directory",
        })?
        .to_path_buf();
    let epoch_json = serde_json::to_value(&material.authority_epoch).map_err(|_| {
        DriveError::Authority(DispatchAuthorityError::InvalidMaterial {
            field: "epoch-shape",
        })
    })?;
    let authority = WasmDispatchAuthority::new(
        &material.claim_id,
        &material.operation_id,
        material.generation,
        &epoch_json,
        &material.launch_nonce,
    )
    .map_err(DriveError::Authority)?;
    let intent = derive_drive_intent(material, &executable, &host_digest, &working_directory)?;
    let now_ms = now_unix_ms()?;
    let request = issue_drive_permit(material, &authority, &intent, now_ms)?;
    let binding = ProcessBinding::from_request(&request);
    let executor = Arc::new(WindowsProcessExecutor::new(Arc::new(
        DriveAuthorityPort::new(authority),
    )));
    let sink: Arc<dyn ProcessEvidenceSink> = Arc::new(BoundedDriveSink::new());
    let mut process = WasmP03ProcessAdapter::new(Arc::clone(&executor), Arc::clone(&sink));
    // Single ownership of the request value: the adapter's staged slot
    // serves the runtime `prepare` path (which needs P-02 launch
    // evidence); the parent drive moves the issued request straight into
    // `start`, then reaps the same operation. No second invocation, no
    // retry of the effect.
    process
        .start(request)
        .map_err(|_| DriveError::Execution { stage: "start" })?;
    let evidence = process
        .reconcile(&binding)
        .map_err(|_| DriveError::Execution { stage: "reap" })?;
    if !matches!(evidence.view().lifecycle(), ProcessLifecycle::Exited) {
        return Err(DriveError::Execution { stage: "reap" });
    }
    let (captured, captured_stderr) = executor
        .captured_output(binding.operation_id())
        .map_err(|_| DriveError::Execution { stage: "capture" })?;
    if !captured.complete || captured.truncated {
        return Err(DriveError::Execution { stage: "capture" });
    }
    let metering_text = if captured_stderr.complete && !captured_stderr.truncated {
        String::from_utf8(captured_stderr.bytes)
            .map_err(|_| DriveError::Execution { stage: "metering" })?
    } else {
        return Err(DriveError::Execution { stage: "metering" });
    };
    let metering =
        parse_metering_line(&metering_text).ok_or(DriveError::Execution { stage: "metering" })?;
    Ok(DispatchDriveResponse {
        operation_id: material.operation_id.clone(),
        component_id: material.ceilings.component_id.clone(),
        artifact_digest: material.ceilings.artifact_digest.as_str().to_owned(),
        input_digest: material.ceilings.input_digest.as_str().to_owned(),
        host_artifact_digest: host_digest.as_str().to_owned(),
        output_digest: Sha256Digest::of_bytes(&captured.bytes).as_str().to_owned(),
        output: captured.bytes,
        fuel_consumed: metering.fuel_consumed,
        peak_memory_bytes: metering.peak_memory_bytes,
        table_elements: u64::from(metering.table_elements),
        epoch_ticks: metering.epoch_ticks,
    })
}

/// `Arc`-shared dispatch authority fronting the executor. The authority is
/// constructed by value in [`drive_material`]; this thin shared wrapper
/// lets the executor hold it without borrowing the drive frame.
struct DriveAuthorityPort {
    authority: WasmDispatchAuthority,
}

impl DriveAuthorityPort {
    fn new(authority: WasmDispatchAuthority) -> Self {
        Self { authority }
    }
}

impl eliot_process_executor::DispatchValidationPort for DriveAuthorityPort {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: eliot_process::SuspendedProcessIdentity,
    ) -> Result<eliot_process::ValidatedDispatch, ProcessExecutionError> {
        self.authority.validate_and_consume(request, observed)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn no_material_stays_denied() {
        // No dispatch file beside the test binary: the drive reports
        // absence without touching process authority. (The test binary
        // directory carries no material file.)
        match drive_dispatch() {
            Err(DriveError::NoMaterial | DriveError::Material(_)) => {}
            other => panic!("drive without material must stay denied, got {other:?}"),
        }
    }

    #[test]
    fn drive_error_codes_are_stable() {
        assert_eq!(
            DriveError::NoMaterial.to_string(),
            "DISPATCH_DRIVE_NO_MATERIAL"
        );
        assert_eq!(
            DriveError::Intent { field: "limits" }.to_string(),
            "DISPATCH_DRIVE_INTENT:limits"
        );
        assert_eq!(
            DriveError::Execution { stage: "start" }.to_string(),
            "DISPATCH_DRIVE_EXECUTION:start"
        );
    }

    /// Canonical intent pin: the derived intent carries exactly the
    /// admitted identities, the resolved image, the `--guest-exec` argv
    /// spellings, and the material ceilings. The owner publisher derives
    /// the identical intent for its join gate; any drift here fails there,
    /// never silently. Pure derivation — no filesystem, no spawn.
    #[test]
    fn derived_intent_binds_admitted_material() {
        use crate::dispatch_authority::ValidatedDispatchGrant;
        use eliot_contracts::EpochId;
        use eliot_process::{ActionLeaseRef, FencingToken, Generation};

        let epoch: EpochId = serde_json::from_value(serde_json::json!({
            "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
            "sequence": 3
        }))
        .expect("test epoch parses");
        let fence = FencingToken::new(
            epoch,
            Generation::new(7).expect("generation"),
            "wasm-host-launch-fence-aaaaaaaaaaaaaaaa".to_owned(),
        )
        .expect("test fence builds");
        let grant = ValidatedDispatchGrant::new(
            fence,
            ActionLeaseRef::new("wasm-host-launch-lease-aaaaaaaaaaaaaaaa".to_owned())
                .expect("lease"),
            "e".repeat(64),
            4_000_000_000_000,
            4_000_000_060_000,
        )
        .expect("test grant validates");
        let material = ValidatedDispatchMaterial {
            claim_id: "claim-intent-001".to_owned(),
            operation_id: "operation-intent-001".to_owned(),
            generation: 7,
            authority_epoch: serde_json::from_value(serde_json::json!({
                "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                "sequence": 3
            }))
            .expect("epoch parses"),
            launch_nonce: "launch-nonce-intent-0001".to_owned(),
            admitted_at_unix_ms: 4_000_000_000_000,
            grant,
            host_artifact_digest: Sha256Digest::of_bytes(b"intent-host-image"),
            profile: crate::cli_contract::Profile::D2Operational,
            ceilings: crate::dispatch_material::ValidatedGuestCeilings {
                component_id: "component-intent".to_owned(),
                artifact_digest: Sha256Digest::of_bytes(b"intent-artifact"),
                input_digest: Sha256Digest::of_bytes(b"intent-input"),
                max_output_bytes: 2048,
                max_fuel: 50_000,
                max_memory_bytes: 131_072,
                wall_deadline_ms: 5_000,
                epoch_deadline_ticks: 50,
            },
            artifact_bytes: b"intent-artifact".to_vec(),
            input_bytes: b"intent-input".to_vec(),
        };
        let executable = Path::new("C:\\Kernel\\eliot-wasm-host.exe");
        let working = Path::new("C:\\Kernel");
        let host_digest = Sha256Digest::of_bytes(b"intent-host-image");
        let intent = derive_drive_intent(&material, executable, &host_digest, working)
            .expect("intent derives");
        // Private fields assert through the canonical JSON shape.
        let shape = serde_json::to_value(&intent).expect("intent serializes");
        assert_eq!(shape["operation_id"], "operation-intent-001");
        assert_eq!(shape["executable"], "C:\\Kernel\\eliot-wasm-host.exe");
        assert_eq!(shape["executable_sha256"], host_digest.as_str());
        let argv = shape["argv"].as_array().expect("argv array");
        let has = |flag: &str| argv.iter().any(|entry| entry == flag);
        assert_eq!(argv[0], "--profile");
        assert_eq!(argv[1], "D2_OPERATIONAL");
        assert_eq!(argv[2], "--guest-exec");
        assert!(has("--guest-exec-artifact-digest"));
        assert!(has(material.ceilings.artifact_digest.as_str()));
        assert!(has("--guest-exec-max-fuel"));
        assert!(has("50000"));
        assert!(has("--guest-exec-epoch-ticks"));
        assert!(has("50"));
    }
}
