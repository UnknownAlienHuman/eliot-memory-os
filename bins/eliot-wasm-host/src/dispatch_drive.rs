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
//! process_tree  = the admitted work-scope identity (distinct type, one
//!                 admitted string: the runtime envelope binds the tree to
//!                 the work scope, and the owner join closes over it)
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

use std::path::Path;
use std::sync::{Arc, Mutex};

use eliot_contracts::{ArtifactId, ContractId, ResourceGeneration, StateFence};
use eliot_governor::{
    ContourAdmission, GovernorWasmAdmission, KernelGenerationSnapshot, PromotionExpectations,
};
use eliot_observation_contracts::ObservationScope;
use eliot_process::{
    EnvironmentInheritance, EnvironmentProjection, EvidenceSinkError, Generation, ImageId, JobId,
    OperationId, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError, ProcessIntent,
    ProcessRequest, ProcessTreeId, ResourceLimits, SessionId,
};
use eliot_process_executor::{WindowsProcessExecutor, wasm_p03_adapter::WasmP03ProcessAdapter};
use eliot_receipts::WorkScopeId;
use eliot_runtime_contracts::{
    HealthDimension, HealthVector, LeaseState, ModuleGeneration, ModuleGenerationState,
    RuntimeLease,
};
use eliot_security_contracts::{
    CompetenceLevel, EffectCeiling, EpistemicUse, FreshnessStatus, IndependenceLevel,
    InstructionTaint, IntegrityStatus, PrivacyClass, QuarantineState, SourceAssurance,
};
use eliot_wasm_runtime::{
    ArtifactAccessLimits, CancellationPolicy, CapabilityId, ComponentManifest, EngineBinding,
    EpochPolicy, ExecutionContour, InvocationId, InvocationLimits, InvocationRequest, OwnerId,
    P03ReceiptVerifierPort, ProcessBinding, Revision, RuntimePorts, Sha256Digest, WasmRuntime,
    WorkScopeRef, WorkUnitId,
};

use crate::child_engine::IsolatedChildEngine;
use crate::dispatch_authority::{DispatchAuthorityError, WasmDispatchAuthority};
use crate::dispatch_material::{MaterialError, ValidatedDispatchMaterial, read_dispatch_material};
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
    /// Admission assembly failed (contour, owner records, factory).
    Admission {
        /// Stable field name.
        field: &'static str,
    },
    /// Invocation assembly or engine invocation failed.
    Invocation {
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
            Self::Admission { field } => write!(formatter, "DISPATCH_DRIVE_ADMISSION:{field}"),
            Self::Invocation { field } => write!(formatter, "DISPATCH_DRIVE_INVOCATION:{field}"),
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
    /// Lifecycle outcome verdicts evaluated from retained evidence.
    pub verdicts: LifecycleVerdicts,
}

/// Lifecycle outcome verdicts (A13.3 promotion path) evaluated from the
/// retained execution evidence of exactly one admitted operation. Shadow
/// is the only phase single-execution evidence can close: a completed,
/// effect-free, differential-agreeing run is the shadow observation
/// itself. Canary, rollback, and cutover are progression phases requiring
/// multi-evidence Governor decisions; they stay unevaluated (matching the
/// codebase convention that unevaluated verdicts read false), never
/// minted as verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleVerdicts {
    /// Effect-free completed differential-agreeing execution observed.
    pub shadow: eliot_wasm_runtime::VerificationVerdict,
    /// Bounded-canary progression evidence (never single-execution).
    pub canary: eliot_wasm_runtime::VerificationVerdict,
    /// Rollback execution evidence (none observed here).
    pub rollback: eliot_wasm_runtime::VerificationVerdict,
    /// Active-generation cutover evidence (none observed here).
    pub cutover: eliot_wasm_runtime::VerificationVerdict,
}

impl LifecycleVerdicts {
    /// All phases unevaluated: the closed value before any execution.
    #[must_use]
    pub const fn unevaluated() -> Self {
        use eliot_wasm_runtime::VerificationVerdict::Rejected;
        Self {
            shadow: Rejected,
            canary: Rejected,
            rollback: Rejected,
            cutover: Rejected,
        }
    }
}

/// Evaluates lifecycle verdicts from the retained Succeeded evidence.
/// The differential already matched (the runtime enforced it for
/// success), so shadow closes exactly when the completed run proposed no
/// effects and left a measured-empty state delta. Absent measurements
/// never manufacture verification: a missing delta reports Rejected.
/// Progression phases stay unevaluated.
fn evaluate_lifecycle_verdicts(result: &eliot_wasm_runtime::InvocationResult) -> LifecycleVerdicts {
    use eliot_wasm_runtime::VerificationVerdict::{Rejected, Verified};
    let shadow = match result.observed_state_delta.as_deref() {
        Some(delta) if delta.is_empty() && result.proposed_effects.is_empty() => Verified,
        _ => Rejected,
    };
    LifecycleVerdicts {
        shadow,
        ..LifecycleVerdicts::unevaluated()
    }
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
) -> Result<crate::installed_binary::InstalledBinary, DriveError> {
    let executable =
        std::env::current_exe().map_err(|_| DriveError::Execution { stage: "locator" })?;
    let binding = WasmHostBinaryBinding::new(executable, material.host_artifact_digest.clone())
        .map_err(DriveError::Resolve)?;
    resolve_installed_binary(&binding).map_err(DriveError::Resolve)
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
        ProcessTreeId::new(material.work.work_scope.clone()).map_err(|_| intent_field("tree"))?,
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

/// Builds the invocation request from admitted identities: invocation and
/// tree bind the operation and claim, work unit and scope bind the work
/// record, the contour binds the material marker, the input is the proven
/// guest bytes, and the seed is owner-set. Cancellation is never
/// requested by the drive.
fn assemble_request(material: &ValidatedDispatchMaterial) -> Result<InvocationRequest, DriveError> {
    let invoked = |field: &'static str| DriveError::Admission { field };
    let contour = match material.work.contour.as_str() {
        "SHADOW" => ExecutionContour::Shadow,
        "CONFORMANCE" => ExecutionContour::Conformance,
        _ => return Err(invoked("contour")),
    };
    InvocationRequest::new(
        InvocationId::new(material.operation_id.clone()).map_err(|_| invoked("invocation-id"))?,
        CapabilityId::new(material.ceilings.component_id.clone())
            .map_err(|_| invoked("component-id"))?,
        WorkUnitId::new(material.work.work_unit.clone()).map_err(|_| invoked("work-unit"))?,
        WorkScopeRef::new(material.work.work_scope.clone()).map_err(|_| invoked("work-scope"))?,
        contour,
        material.input_bytes.clone(),
        material.work.deterministic_seed,
        false,
    )
    .map_err(|_| invoked("request"))
}

/// Builds the closed-world generation manifest from material records plus
/// recomputed digests, then runs the documented contour admission over
/// real bytes: default WASM decision, digest re-hash, empty actual
/// imports, and request binding. Returns the manifest for owner assembly
/// plus the admitted generation the request must match.
fn contour_admission(
    material: &ValidatedDispatchMaterial,
    request: &InvocationRequest,
) -> Result<
    (
        crate::contour::GenerationManifest,
        crate::contour::AdmittedGeneration,
    ),
    DriveError,
> {
    let denied = |field: &'static str| DriveError::Admission { field };
    let manifest = crate::contour::GenerationManifest {
        component_id: material.manifest.component_id.clone(),
        target: material.manifest.target.clone(),
        artifact_digest: Sha256Digest::of_bytes(&material.artifact_bytes),
        wit_digest: Sha256Digest::of_bytes(crate::wasmtime_provider::guest_wit_bytes()),
        world: material.manifest.world.clone(),
        allowed_imports: Vec::new(),
        allowed_exports: vec!["run".to_owned()],
        capability_grants: Vec::new(),
        limits: assemble_limits(material)?,
        state_class: material.manifest.state_class.clone(),
        migration_contract: material.manifest.migration_contract.clone(),
        privacy_policy: material.manifest.privacy_policy.clone(),
        comparator: material.manifest.comparator.clone(),
        rollback_generation: material.manifest.rollback_generation.clone(),
    };
    if manifest.artifact_digest != material.ceilings.artifact_digest
        || manifest.component_id != material.ceilings.component_id
    {
        return Err(denied("manifest-agreement"));
    }
    let decision = crate::contour::PrototypeContourDecision::default_for_new_prototype();
    let admitted = crate::contour::admit_generation_with_bytes(
        Some(&decision),
        &manifest,
        &[],
        &material.artifact_bytes,
        &crate::wasmtime_provider::guest_wit_bytes(),
    )
    .map_err(|_| denied("contour-admission"))?;
    crate::contour::check_admitted_request(&admitted, request)
        .map_err(|_| denied("request-binding"))?;
    Ok((manifest, admitted))
}

/// Assembles the per-invocation limit envelope from material ceilings plus
/// frozen contour constants. Input ceiling tracks the real input length
/// (ceilings bound, never shrink, reality); host-call ceiling stays at the
/// closed-world minimum; stack and cancellation stay provider-pinned.
fn assemble_limits(material: &ValidatedDispatchMaterial) -> Result<InvocationLimits, DriveError> {
    let ceilings = &material.ceilings;
    let limited = |field: &'static str| DriveError::Admission { field };
    Ok(InvocationLimits {
        max_input_bytes: (material.input_bytes.len() as u64).max(1),
        max_output_bytes: ceilings.max_output_bytes,
        max_host_calls: 1,
        max_fuel: ceilings.max_fuel,
        max_memory_bytes: ceilings.max_memory_bytes,
        max_table_elements: u32::try_from(ceilings.table_elements)
            .map_err(|_| limited("table-elements"))?,
        max_instances: u32::try_from(ceilings.max_instances).map_err(|_| limited("instances"))?,
        max_stack_bytes: crate::wasmtime_provider::PROVIDER_STACK_SIZE as u64,
        wall_deadline_ms: ceilings.wall_deadline_ms,
        epoch: EpochPolicy {
            deadline_ticks: ceilings.epoch_deadline_ticks,
            cancellation: CancellationPolicy::EpochAndFuel,
        },
        artifact_access: ArtifactAccessLimits {
            allowed_digests: [ceilings.artifact_digest.clone()].into_iter().collect(),
            max_reads: u32::try_from(ceilings.artifact_access_reads)
                .map_err(|_| limited("artifact-reads"))?,
            max_bytes: ceilings.artifact_access_bytes,
        },
    })
}

/// Assembles the component manifest from material records plus recomputed
/// digests. The engine binding is the shared grant-derived object, so the
/// engine gate binds the exact authorized digests; interface and
/// configuration digests recompute from the frozen bytes.
fn assemble_component_manifest(
    material: &ValidatedDispatchMaterial,
    engine_binding: &EngineBinding,
) -> Result<ComponentManifest, DriveError> {
    let manifested = |field: &'static str| DriveError::Admission { field };
    let privacy = material
        .manifest
        .privacy_classes
        .iter()
        .map(|class| match class.as_str() {
            "Public" => Ok(PrivacyClass::Public),
            "Internal" => Ok(PrivacyClass::Internal),
            "Private" => Ok(PrivacyClass::Private),
            "Secret" => Ok(PrivacyClass::Secret),
            "Licensed" => Ok(PrivacyClass::Licensed),
            _ => Err(manifested("privacy-class")),
        })
        .collect::<Result<Vec<PrivacyClass>, DriveError>>()?;
    Ok(ComponentManifest {
        component_id: CapabilityId::new(material.manifest.component_id.clone())
            .map_err(|_| manifested("component-id"))?,
        world: CapabilityId::new(material.manifest.world.clone())
            .map_err(|_| manifested("world"))?,
        wit_version: crate::wasmtime_provider::WIT_VERSION.to_owned(),
        guest_target: material.manifest.target.clone(),
        artifact_digest: Sha256Digest::of_bytes(&material.artifact_bytes),
        interface_digest: Sha256Digest::of_bytes(crate::wasmtime_provider::guest_wit_bytes()),
        source_digest: material.manifest.source_digest.clone(),
        configuration_digest: crate::wasmtime_provider::provider_configuration_digest(),
        state_contract_digest: material.manifest.state_contract_digest.clone(),
        imports: Default::default(),
        exports: [CapabilityId::new("run").map_err(|_| manifested("exports"))?]
            .into_iter()
            .collect(),
        admitted_privacy_classes: privacy,
        required_verifier: material.manifest.required_verifier.clone(),
        engine: engine_binding.clone(),
    })
}

/// Maps one owner spelling to its health dimension; unknown spellings fail
/// closed so owner and child can never disagree silently.
fn map_health_dimension(value: &str) -> Result<HealthDimension, DriveError> {
    match value {
        "UNKNOWN" => Ok(HealthDimension::Unknown),
        "HEALTHY" => Ok(HealthDimension::Healthy),
        "DEGRADED" => Ok(HealthDimension::Degraded),
        "FAILED" => Ok(HealthDimension::Failed),
        _ => Err(DriveError::Admission {
            field: "health-dimension",
        }),
    }
}

/// Assembles the owner records for the Governor factory: snapshot,
/// generation, lease, owner, scope, assurance, limits, revisions, caps,
/// promotion. Fences derive from the snapshot (recovery state); the grant
/// fence agrees with it by material validation. Every enum spelling maps
/// strictly; unknown spellings fail closed.
#[allow(clippy::too_many_lines)]
fn assemble_owner_records(
    material: &ValidatedDispatchMaterial,
) -> Result<OwnerRecords, DriveError> {
    let owned = |field: &'static str| DriveError::Admission { field };
    let snapshot = KernelGenerationSnapshot {
        service: material.snapshot.service.clone(),
        protocol: material.snapshot.protocol.clone(),
        generation: ResourceGeneration::new(material.snapshot.generation)
            .map_err(|_| owned("snapshot-generation"))?,
        authority_epoch: material.snapshot.authority_epoch.clone(),
        artifact_digest: material.snapshot.artifact_digest.as_str().to_owned(),
        protected_snapshot_digest: material
            .snapshot
            .protected_snapshot_digest
            .as_str()
            .to_owned(),
        principal: material.snapshot.principal.clone(),
    };
    snapshot
        .validate()
        .map_err(|_| owned("snapshot-validate"))?;
    let fence = snapshot.state_fence();
    let generation = ModuleGeneration {
        module_id: ContractId::new(material.manifest.component_id.clone())
            .map_err(|_| owned("module-id"))?,
        generation: ResourceGeneration::new(material.grant.fence_generation())
            .map_err(|_| owned("fence-generation"))?,
        artifact_id: ArtifactId::new(material.ceilings.artifact_digest.as_str().to_owned())
            .map_err(|_| owned("artifact-id"))?,
        state: match material.work.generation_state.as_str() {
            "ready" => ModuleGenerationState::Ready,
            "active" => ModuleGenerationState::Active,
            _ => return Err(owned("generation-state")),
        },
        health: {
            let dimensions = material
                .work
                .generation_health
                .iter()
                .map(|dimension| map_health_dimension(dimension))
                .collect::<Result<Vec<HealthDimension>, DriveError>>()?;
            let [
                liveness,
                readiness,
                freshness,
                compatibility,
                integrity,
                capacity,
            ] = dimensions.try_into().map_err(|_| owned("health-vector"))?;
            HealthVector {
                liveness,
                readiness,
                freshness,
                compatibility,
                integrity,
                capacity,
            }
        },
        state_fence: fence.clone(),
    };
    let lease = RuntimeLease {
        lease_id: material.work.lease_id.clone(),
        scope_ref: material.work.lease_scope_ref.clone(),
        authority_epoch: material.authority_epoch.clone(),
        state_fence: fence.clone(),
        state: match material.work.lease_state.as_str() {
            "active" => LeaseState::Active,
            _ => return Err(owned("lease-state")),
        },
    };
    let owner = OwnerId::new(material.work.owner.clone()).map_err(|_| owned("owner"))?;
    let work_unit =
        WorkUnitId::new(material.work.work_unit.clone()).map_err(|_| owned("work-unit"))?;
    let work_scope = ObservationScope {
        work_scope: WorkScopeId::new(material.work.work_scope.clone())
            .map_err(|_| owned("work-scope"))?,
        task_ref: material.work.task_ref.clone(),
        attempt_ref: Some(material.work.work_unit.clone()),
        module_or_route_ref: Some(material.ceilings.component_id.clone()),
    };
    let assurance = SourceAssurance {
        source_ref: material.assurance.source_ref.clone(),
        provenance_ref: material.assurance.provenance_ref.clone(),
        integrity: match material.assurance.integrity.as_str() {
            "VERIFIED" => IntegrityStatus::Verified,
            "UNVERIFIED" => IntegrityStatus::Unverified,
            "MODIFIED" => IntegrityStatus::Modified,
            "CONFLICTED" => IntegrityStatus::Conflicted,
            _ => return Err(owned("assurance-integrity")),
        },
        freshness: match material.assurance.freshness.as_str() {
            "CURRENT" => FreshnessStatus::Current,
            "STALE" => FreshnessStatus::Stale,
            "UNKNOWN" => FreshnessStatus::Unknown,
            _ => return Err(owned("assurance-freshness")),
        },
        competence: match material.assurance.competence.as_str() {
            "DOMAIN_VERIFIED" => CompetenceLevel::DomainVerified,
            "ATTRIBUTED" => CompetenceLevel::Attributed,
            "UNKNOWN" => CompetenceLevel::Unknown,
            _ => return Err(owned("assurance-competence")),
        },
        independence: match material.assurance.independence.as_str() {
            "INDEPENDENT" => IndependenceLevel::Independent,
            "RELATED" => IndependenceLevel::Related,
            "COMMON_MODE" => IndependenceLevel::CommonMode,
            "UNKNOWN" => IndependenceLevel::Unknown,
            _ => return Err(owned("assurance-independence")),
        },
        privacy_class: match material.assurance.privacy_class.as_str() {
            "PUBLIC" => PrivacyClass::Public,
            "INTERNAL" => PrivacyClass::Internal,
            "PRIVATE" => PrivacyClass::Private,
            "SECRET" => PrivacyClass::Secret,
            "LICENSED" => PrivacyClass::Licensed,
            _ => return Err(owned("assurance-privacy")),
        },
        instruction_taint: match material.assurance.instruction_taint.as_str() {
            "CLEARED" => InstructionTaint::Cleared,
            "DATA_ONLY" => InstructionTaint::DataOnly,
            "UNTRUSTED" => InstructionTaint::Untrusted,
            "COMMAND_LIKE" => InstructionTaint::CommandLike,
            _ => return Err(owned("assurance-taint")),
        },
        allowed_epistemic_use: material
            .assurance
            .epistemic_use
            .iter()
            .map(|use_verb| match use_verb.as_str() {
                "OBSERVATION" => Ok(EpistemicUse::Observation),
                "ATTRIBUTED_INPUT" => Ok(EpistemicUse::AttributedInput),
                "CANDIDATE_EVIDENCE" => Ok(EpistemicUse::CandidateEvidence),
                "VERIFICATION_INPUT" => Ok(EpistemicUse::VerificationInput),
                _ => Err(owned("assurance-epistemic")),
            })
            .collect::<Result<Vec<EpistemicUse>, DriveError>>()?,
        allowed_effects: material
            .assurance
            .effect_ceilings
            .iter()
            .map(|ceiling| match ceiling.as_str() {
                "READ_ONLY" => Ok(EffectCeiling::ReadOnly),
                "CANDIDATE_ONLY" => Ok(EffectCeiling::CandidateOnly),
                "NO_EXTERNAL_EFFECT" => Ok(EffectCeiling::NoExternalEffect),
                _ => Err(owned("assurance-effects")),
            })
            .collect::<Result<Vec<EffectCeiling>, DriveError>>()?,
        required_verifier: Some(material.assurance.required_verifier.clone()),
        quarantine: match material.assurance.quarantine.as_str() {
            "NONE" => QuarantineState::None,
            "REVIEW_REQUIRED" => QuarantineState::ReviewRequired,
            "QUARANTINED" => QuarantineState::Quarantined,
            "RELEASED" => QuarantineState::Released,
            _ => return Err(owned("assurance-quarantine")),
        },
        state_fence: fence,
    };
    Ok(OwnerRecords {
        snapshot,
        generation,
        lease,
        owner,
        work_unit,
        work_scope,
        assurance,
    })
}

/// Owner records assembled for one Governor factory call.
struct OwnerRecords {
    snapshot: KernelGenerationSnapshot,
    generation: ModuleGeneration,
    lease: RuntimeLease,
    owner: OwnerId,
    work_unit: WorkUnitId,
    work_scope: ObservationScope,
    assurance: SourceAssurance,
}

/// Acquires admission from the existing Governor factory over owner
/// records: contour observations re-hash real bytes, coherence re-proves
/// generation/lease/assurance/scope/verifier agreement, and every receipt
/// digest recomputes from retained content. Nothing here mints authority;
/// the factory denies incoherence fail-closed.
fn acquire_admission(
    material: &ValidatedDispatchMaterial,
    engine_binding: &EngineBinding,
    admitted: &crate::contour::AdmittedGeneration,
) -> Result<GovernorWasmAdmission, DriveError> {
    let owners = assemble_owner_records(material)?;
    let manifest = assemble_component_manifest(material, engine_binding)?;
    let contour = ContourAdmission {
        artifact_bytes: material.artifact_bytes.clone(),
        wit_bytes: crate::wasmtime_provider::guest_wit_bytes().to_vec(),
        configuration_bytes: crate::wasmtime_provider::provider_configuration_bytes().to_vec(),
        admitted_artifact: material.ceilings.artifact_digest.clone(),
        admitted_wit: Sha256Digest::of_bytes(crate::wasmtime_provider::guest_wit_bytes()),
        admitted_world: admitted.world().to_owned(),
        admitted_target: admitted.target().to_owned(),
    };
    let promotion = PromotionExpectations {
        corpus_digest: material.promotion.corpus_digest.clone(),
        expected_result_digest: material.promotion.expected_result_digest.clone(),
        expected_effect_digest: material.promotion.expected_effect_digest.clone(),
        expected_state_delta_digest: material.promotion.expected_state_delta_digest.clone(),
    };
    let limits = assemble_limits(material)?;
    GovernorWasmAdmission::from_owners(
        &owners.snapshot,
        manifest,
        &contour,
        owners.generation,
        owners.lease,
        owners.owner,
        owners.work_unit,
        owners.work_scope,
        owners.assurance,
        limits,
        Revision::new(material.work.authority_revision).map_err(|_| DriveError::Admission {
            field: "authority-revision",
        })?,
        Revision::new(material.work.lifecycle_revision).map_err(|_| DriveError::Admission {
            field: "lifecycle-revision",
        })?,
        Revision::new(material.work.verification_revision).map_err(|_| DriveError::Admission {
            field: "verification-revision",
        })?,
        Default::default(),
        Default::default(),
        promotion,
    )
    .map_err(|_| DriveError::Admission {
        field: "from-owners",
    })
}

/// Builds the shared grant-derived engine binding. Called once per drive;
/// the same object feeds manifest assembly and engine seating so the
/// engine gate binds the exact authorized digests.
fn engine_binding_for(installed: &crate::installed_binary::InstalledBinary) -> EngineBinding {
    crate::grant_launch::grant_engine_binding(installed)
}
/// Drives one admitted dispatch to the canonical response through the
/// documented admission path and the existing isolated child engine:
/// contour admission over real bytes, owner-record assembly, Governor
/// factory admission, invocation request, one-shot issue, real start,
/// engine invocation over the reaped child, canonical response. The child
/// execution is real; every boundary fails closed (never a fabricated
/// byte, never minted authority).
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
    // Installed image first: the engine binding, intent executable, and
    // installation records all flow from this single resolution.
    let installed = resolve_drive_image(material)?;
    let executable = installed.path().to_path_buf();
    let host_digest = installed.digest().clone();
    // Shared grant-derived engine binding: the same object feeds manifest
    // assembly and engine seating so the engine gate binds the exact
    // authorized digests.
    let engine_binding = engine_binding_for(&installed);
    // Invocation request from admitted identities: invocation and tree
    // bind the operation and claim so the runtime coherence rules close
    // over admitted values, never minted ones.
    let request = assemble_request(material)?;
    // Contour admission over real bytes: manifest assembly, default WASM
    // decision, byte re-hash, request binding. A divergent fixture is
    // denied before any authority, permit, or child exists.
    let (_, admitted) = contour_admission(material, &request)?;
    // Owner records + Governor factory: snapshot, generation, lease,
    // owner, scope, assurance, limits, revisions, caps, promotion. The
    // factory re-proves coherence and re-hashes digests; its receipts are
    // recomputed from retained content, never minted.
    let admission = acquire_admission(material, &engine_binding, &admitted)?;
    // Live resolutions from the retained admission happen inside the
    // runtime execute below; the drive does not resolve twice.
    // One-shot issue over the derived authority. The issued request binds
    // the runtime envelope the owner join closes.
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
    let dispatch_authority = WasmDispatchAuthority::new(
        &material.claim_id,
        &material.operation_id,
        material.generation,
        &epoch_json,
        &material.launch_nonce,
    )
    .map_err(DriveError::Authority)?;
    let intent = derive_drive_intent(material, &executable, &host_digest, &working_directory)?;
    let now_ms = now_unix_ms()?;
    let issued = issue_drive_permit(material, &dispatch_authority, &intent, now_ms)?;
    let executor = Arc::new(WindowsProcessExecutor::new(Arc::new(
        DriveAuthorityPort::new(dispatch_authority),
    )));
    let sink: Arc<dyn ProcessEvidenceSink> = Arc::new(BoundedDriveSink::new());
    // Engine seating from the authorized grant (deadline enforced; the
    // wire accept path is absent on this channel). The binding is the
    // shared grant-derived object, so the engine gate binds the exact
    // authorized digests.
    if material.grant.expires_at() <= now_ms {
        return Err(DriveError::Authority(DispatchAuthorityError::Unavailable {
            field: "grant-window",
        }));
    }
    let accepted = accepted_from_material(material, &executable, &host_digest)?;
    let executable_text = executable.to_str().ok_or(DriveError::Invocation {
        field: "executable",
    })?;
    let authorized = crate::grant_authorization::authorize_grant(
        &accepted,
        executable_text,
        &host_digest,
        &material.artifact_bytes,
        &crate::wasmtime_provider::guest_wit_bytes(),
    )
    .map_err(|_| DriveError::Invocation { field: "authorize" })?;
    let engine = IsolatedChildEngine::for_authorized_grant(
        Arc::clone(&executor),
        Arc::clone(&sink),
        engine_binding,
        &authorized,
        crate::wasmtime_provider::provider_configuration_digest(),
    );
    // Retain the full port set: the SAME admission object backs all four
    // resolution ports, the process adapter fronts the derived authority,
    // the receipt verifier re-proves binding/receipt/envelope agreement,
    // and the engine is seated above. Then stage the issued request for
    // the runtime prepare path and execute through the retained ports:
    // resolve, prepare, start, invoke, and classify (including the
    // differential and lifecycle gates) all run inside.
    let process = WasmP03ProcessAdapter::new(Arc::clone(&executor), Arc::clone(&sink));
    process
        .stage_admitted_request(issued)
        .map_err(|_| DriveError::Execution { stage: "stage" })?;
    let ports = RuntimePorts::new(
        Box::new(admission.clone()),
        Box::new(admission.clone()),
        Box::new(admission.clone()),
        Box::new(admission),
        Box::new(process),
        Box::new(DriveReceiptVerifier),
        Box::new(engine),
    );
    let mut runtime = WasmRuntime::new(Some(ports));
    let result = runtime.execute(request);
    map_invocation_result(&result, material, &host_digest)
}

/// Derives the snapshot fence the accepted grant carries: the snapshot
/// epoch plus the snapshot generation, both enforced equal to the grant
/// fence at material validation.
fn snapshot_fence(material: &ValidatedDispatchMaterial) -> Result<StateFence, DriveError> {
    let generation = ResourceGeneration::new(material.snapshot.generation).map_err(|_| {
        DriveError::Admission {
            field: "snapshot-generation",
        }
    })?;
    Ok(StateFence::new(
        material.snapshot.authority_epoch.clone(),
        generation,
    ))
}

/// Builds the wire-accepted grant observations from owner-channel records:
/// digests recompute from real bytes, fence and epoch thread the snapshot
/// and grant, nonce and deadline thread the material, and the host binding
/// names the resolved image. The authorize call re-proves bytes and
/// binding; this constructor shapes, never proves.
fn accepted_from_material(
    material: &ValidatedDispatchMaterial,
    executable: &Path,
    host_digest: &Sha256Digest,
) -> Result<crate::grant_client::AcceptedGrant, DriveError> {
    let executable_text = executable.to_str().ok_or(DriveError::Invocation {
        field: "executable",
    })?;
    Ok(crate::grant_client::AcceptedGrant {
        component_id: material.ceilings.component_id.clone(),
        artifact_digest: Sha256Digest::of_bytes(&material.artifact_bytes),
        interface_digest: Sha256Digest::of_bytes(crate::wasmtime_provider::guest_wit_bytes()),
        fence: snapshot_fence(material)?,
        epoch: material.authority_epoch.clone(),
        nonce: material.launch_nonce.clone(),
        deadline_unix_ms: material.grant.expires_at(),
        host_executable_path: executable_text.to_owned(),
        host_artifact_digest: host_digest.clone(),
    })
}

/// Maps a classified invocation result to the canonical drive response:
/// success carries the real guest output with recomputed digests and
/// measured metering; differential and promotion denials surface as
/// admission taxonomy (owner-data mismatch, never fabricated output);
/// every other verdict fails closed with unknown outcome preserved.
fn map_invocation_result(
    result: &eliot_wasm_runtime::InvocationResult,
    material: &ValidatedDispatchMaterial,
    host_digest: &Sha256Digest,
) -> Result<DispatchDriveResponse, DriveError> {
    use eliot_wasm_runtime::{InvocationDisposition, RuntimeError};
    match (&result.receipt.disposition, &result.receipt.error) {
        (InvocationDisposition::Succeeded, _) => {}
        (InvocationDisposition::Rejected, Some(RuntimeError::DifferentialMismatch)) => {
            return Err(DriveError::Admission {
                field: "differential",
            });
        }
        (InvocationDisposition::Rejected, Some(RuntimeError::PromotionDenied)) => {
            return Err(DriveError::Admission { field: "promotion" });
        }
        (InvocationDisposition::Rejected, _) => {
            return Err(DriveError::Execution { stage: "rejected" });
        }
        (InvocationDisposition::Unavailable, _) => {
            return Err(DriveError::Execution {
                stage: "unavailable",
            });
        }
        (InvocationDisposition::Unknown, _) => {
            return Err(DriveError::Execution { stage: "unknown" });
        }
    }
    let output = result
        .output
        .clone()
        .ok_or(DriveError::Execution { stage: "response" })?;
    let usage = result
        .receipt
        .usage
        .clone()
        .ok_or(DriveError::Execution { stage: "response" })?;
    let peak = usage
        .peak_memory_bytes
        .ok_or(DriveError::Execution { stage: "metering" })?;
    let tables = usage
        .table_elements
        .ok_or(DriveError::Execution { stage: "metering" })?;
    let ticks = usage
        .epoch_ticks
        .ok_or(DriveError::Execution { stage: "metering" })?;
    Ok(DispatchDriveResponse {
        operation_id: material.operation_id.clone(),
        component_id: material.ceilings.component_id.clone(),
        artifact_digest: material.ceilings.artifact_digest.as_str().to_owned(),
        input_digest: material.ceilings.input_digest.as_str().to_owned(),
        host_artifact_digest: host_digest.as_str().to_owned(),
        output_digest: Sha256Digest::of_bytes(&output).as_str().to_owned(),
        output,
        fuel_consumed: usage.fuel_consumed,
        peak_memory_bytes: peak,
        table_elements: u64::from(tables),
        epoch_ticks: ticks,
        verdicts: evaluate_lifecycle_verdicts(result),
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

/// Narrow P-03 receipt verifier: re-proves binding/receipt/envelope
/// agreement on real records without minting proof. Start requires the
/// receipt to name the bound operation and digest plus the envelope
/// invocation; cancellation (never driven here) checks the same binding;
/// reconciliation requires a terminal lifecycle on the bound operation.
struct DriveReceiptVerifier;

impl P03ReceiptVerifierPort for DriveReceiptVerifier {
    fn verify_start(
        &mut self,
        binding: &ProcessBinding,
        receipt: &eliot_process::ProcessStartReceipt,
        envelope: &eliot_wasm_runtime::ProcessLaunchEnvelope,
    ) -> Result<(), eliot_wasm_runtime::PortError> {
        use eliot_wasm_runtime::PortError;
        if receipt.operation_id() != binding.operation_id()
            || receipt.request_digest() != binding.request_digest()
            || envelope.invocation_id.as_str() != binding.operation_id().as_str()
        {
            return Err(PortError::Denied);
        }
        Ok(())
    }

    fn verify_cancellation(
        &mut self,
        binding: &ProcessBinding,
        _receipt: &eliot_process::CancellationReceipt,
        envelope: &eliot_wasm_runtime::ProcessLaunchEnvelope,
    ) -> Result<(), eliot_wasm_runtime::PortError> {
        use eliot_wasm_runtime::PortError;
        if envelope.invocation_id.as_str() != binding.operation_id().as_str() {
            return Err(PortError::Denied);
        }
        Ok(())
    }

    fn verify_reconciliation(
        &mut self,
        binding: &ProcessBinding,
        evidence: &eliot_process::ProcessEvidence,
        envelope: &eliot_wasm_runtime::ProcessLaunchEnvelope,
    ) -> Result<(), eliot_wasm_runtime::PortError> {
        use eliot_wasm_runtime::PortError;
        if envelope.invocation_id.as_str() != binding.operation_id().as_str() {
            return Err(PortError::Denied);
        }
        if !evidence.view().lifecycle().is_terminal() {
            return Err(PortError::UnknownOutcome);
        }
        Ok(())
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
        assert_eq!(
            DriveError::Admission {
                field: "contour-admission"
            }
            .to_string(),
            "DISPATCH_DRIVE_ADMISSION:contour-admission"
        );
        assert_eq!(
            DriveError::Invocation { field: "invoke" }.to_string(),
            "DISPATCH_DRIVE_INVOCATION:invoke"
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
            manifest: crate::dispatch_material::ValidatedManifestRecord {
                component_id: "component-intent".to_owned(),
                world: "eliot:wasm/guest".to_owned(),
                target: "wasm32-wasip2".to_owned(),
                source_digest: Sha256Digest::of_bytes(b"intent-artifact"),
                state_contract_digest: Sha256Digest::of_bytes(b"intent-state"),
                required_verifier: "verifier:intent".to_owned(),
                privacy_classes: vec!["Internal".to_owned()],
                state_class: "stateless".to_owned(),
                migration_contract: "none".to_owned(),
                privacy_policy: "project_code".to_owned(),
                comparator: "shadow-exact".to_owned(),
                rollback_generation: None,
            },
            work: crate::dispatch_material::ValidatedWorkRecord {
                owner: "owner-intent".to_owned(),
                work_unit: "work-intent".to_owned(),
                work_scope: "scope-intent".to_owned(),
                task_ref: None,
                lease_id: "lease-intent".to_owned(),
                lease_scope_ref: "scope-intent".to_owned(),
                lease_state: "active".to_owned(),
                generation_state: "ready".to_owned(),
                authority_revision: 1,
                lifecycle_revision: 1,
                verification_revision: 1,
                deterministic_seed: 7,
                contour: "CONFORMANCE".to_owned(),
                generation_health: vec!["HEALTHY".to_owned(); 6],
            },
            assurance: crate::dispatch_material::ValidatedAssuranceRecord {
                source_ref: "source-intent".to_owned(),
                provenance_ref: "provenance-intent".to_owned(),
                integrity: "VERIFIED".to_owned(),
                freshness: "CURRENT".to_owned(),
                competence: "DOMAIN_VERIFIED".to_owned(),
                independence: "INDEPENDENT".to_owned(),
                privacy_class: "INTERNAL".to_owned(),
                instruction_taint: "DATA_ONLY".to_owned(),
                epistemic_use: vec!["VERIFICATION_INPUT".to_owned()],
                effect_ceilings: vec!["NO_EXTERNAL_EFFECT".to_owned()],
                required_verifier: "verifier:intent".to_owned(),
                quarantine: "NONE".to_owned(),
            },
            promotion: crate::dispatch_material::ValidatedPromotionRecord {
                corpus_digest: Sha256Digest::of_bytes(b"intent-corpus"),
                expected_result_digest: Sha256Digest::of_bytes(b"intent-result"),
                expected_effect_digest: Sha256Digest::of_bytes(b"intent-effects"),
                expected_state_delta_digest: Sha256Digest::of_bytes(b"intent-delta"),
            },
            snapshot: crate::dispatch_material::ValidatedSnapshotRecord {
                service: "eliot-kernel".to_owned(),
                protocol: "eliot.kernel.v1".to_owned(),
                generation: 7,
                authority_epoch: serde_json::from_value(serde_json::json!({
                    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                    "sequence": 3
                }))
                .expect("epoch parses"),
                artifact_digest: Sha256Digest::of_bytes(b"intent-kernel"),
                protected_snapshot_digest: Sha256Digest::of_bytes(b"intent-snapshot"),
                principal: "S-1-5-18".to_owned(),
            },
            ceilings: crate::dispatch_material::ValidatedGuestCeilings {
                component_id: "component-intent".to_owned(),
                artifact_digest: Sha256Digest::of_bytes(b"intent-artifact"),
                input_digest: Sha256Digest::of_bytes(b"intent-input"),
                max_output_bytes: 2048,
                max_fuel: 50_000,
                max_memory_bytes: 131_072,
                wall_deadline_ms: 5_000,
                epoch_deadline_ticks: 50,
                table_elements: 64,
                max_instances: 2,
                artifact_access_reads: 2,
                artifact_access_bytes: 131_072,
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

    /// Full admission fixture from real bytes: the checked-in guest
    /// component compiled through the existing `wat` conversion path plus
    /// a live input, with owner-consistent records throughout.
    fn admission_material(artifact: &[u8], input: &[u8]) -> ValidatedDispatchMaterial {
        use crate::dispatch_authority::ValidatedDispatchGrant;
        use eliot_contracts::EpochId;
        use eliot_process::{ActionLeaseRef, FencingToken, Generation};

        let epoch: EpochId = serde_json::from_value(serde_json::json!({
            "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
            "sequence": 3
        }))
        .expect("test epoch parses");
        let fence = FencingToken::new(
            epoch.clone(),
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
        ValidatedDispatchMaterial {
            claim_id: "claim-admit-001".to_owned(),
            operation_id: "operation-admit-001".to_owned(),
            generation: 7,
            authority_epoch: epoch,
            launch_nonce: "launch-nonce-admit-0001".to_owned(),
            admitted_at_unix_ms: 4_000_000_000_000,
            grant,
            host_artifact_digest: Sha256Digest::of_bytes(b"admit-host-image"),
            profile: crate::cli_contract::Profile::D2Operational,
            manifest: crate::dispatch_material::ValidatedManifestRecord {
                component_id: "component-admit".to_owned(),
                world: "eliot:wasm/guest".to_owned(),
                target: "wasm32-wasip2".to_owned(),
                source_digest: Sha256Digest::of_bytes(artifact),
                state_contract_digest: Sha256Digest::of_bytes(b"admit-state"),
                required_verifier: "verifier:admit".to_owned(),
                privacy_classes: vec!["Internal".to_owned()],
                state_class: "stateless".to_owned(),
                migration_contract: "none".to_owned(),
                privacy_policy: "project_code".to_owned(),
                comparator: "shadow-exact".to_owned(),
                rollback_generation: None,
            },
            work: crate::dispatch_material::ValidatedWorkRecord {
                owner: "owner-admit".to_owned(),
                work_unit: "work-admit".to_owned(),
                work_scope: "scope-admit".to_owned(),
                task_ref: None,
                lease_id: "lease-admit".to_owned(),
                lease_scope_ref: "scope-admit".to_owned(),
                lease_state: "active".to_owned(),
                generation_state: "ready".to_owned(),
                authority_revision: 1,
                lifecycle_revision: 1,
                verification_revision: 1,
                deterministic_seed: 7,
                contour: "CONFORMANCE".to_owned(),
                generation_health: vec!["HEALTHY".to_owned(); 6],
            },
            assurance: crate::dispatch_material::ValidatedAssuranceRecord {
                source_ref: "source-admit".to_owned(),
                provenance_ref: "provenance-admit".to_owned(),
                integrity: "VERIFIED".to_owned(),
                freshness: "CURRENT".to_owned(),
                competence: "DOMAIN_VERIFIED".to_owned(),
                independence: "INDEPENDENT".to_owned(),
                privacy_class: "INTERNAL".to_owned(),
                instruction_taint: "DATA_ONLY".to_owned(),
                epistemic_use: vec!["VERIFICATION_INPUT".to_owned()],
                effect_ceilings: vec!["NO_EXTERNAL_EFFECT".to_owned()],
                required_verifier: "verifier:admit".to_owned(),
                quarantine: "NONE".to_owned(),
            },
            promotion: crate::dispatch_material::ValidatedPromotionRecord {
                corpus_digest: Sha256Digest::of_bytes(b"admit-corpus"),
                expected_result_digest: Sha256Digest::of_bytes(b"admit-result"),
                expected_effect_digest: Sha256Digest::of_bytes(b"admit-effects"),
                expected_state_delta_digest: Sha256Digest::of_bytes(b"admit-delta"),
            },
            snapshot: crate::dispatch_material::ValidatedSnapshotRecord {
                service: "eliot-kernel".to_owned(),
                protocol: "eliot.kernel.v1".to_owned(),
                generation: 7,
                authority_epoch: serde_json::from_value(serde_json::json!({
                    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                    "sequence": 3
                }))
                .expect("epoch parses"),
                artifact_digest: Sha256Digest::of_bytes(b"admit-kernel"),
                protected_snapshot_digest: Sha256Digest::of_bytes(b"admit-snapshot"),
                principal: "S-1-5-18".to_owned(),
            },
            ceilings: crate::dispatch_material::ValidatedGuestCeilings {
                component_id: "component-admit".to_owned(),
                artifact_digest: Sha256Digest::of_bytes(artifact),
                input_digest: Sha256Digest::of_bytes(input),
                max_output_bytes: 4096,
                max_fuel: 100_000,
                max_memory_bytes: 536_870_912,
                wall_deadline_ms: 30_000,
                epoch_deadline_ticks: 100,
                table_elements: 64,
                max_instances: 2,
                artifact_access_reads: 2,
                artifact_access_bytes: 131_072,
            },
            artifact_bytes: artifact.to_vec(),
            input_bytes: input.to_vec(),
        }
    }

    fn real_component() -> Vec<u8> {
        wat::parse_file("tests/fixtures/guest.wat").expect("guest component compiles")
    }

    /// Documented admission over real bytes: request, contour admission
    /// with byte re-hash, owner factory coherence, and live port
    /// resolutions — all green on owner-consistent material, with receipts
    /// bound to the recomputed records.
    #[test]
    fn admission_path_binds_real_bytes() {
        let artifact = real_component();
        let input = b"admission-live-input".to_vec();
        let material = admission_material(&artifact, &input);
        let request = assemble_request(&material).expect("request assembles");
        assert_eq!(request.component_id.as_str(), "component-admit");
        let (_, admitted) = contour_admission(&material, &request).expect("contour admits");
        assert_eq!(admitted.component_id(), "component-admit");
        assert_eq!(
            admitted.artifact_digest().as_str(),
            Sha256Digest::of_bytes(&artifact).as_str()
        );
        let mut admission = acquire_admission(&material, &engine_binding_for_test(), &admitted)
            .expect("factory admits");
        let governor =
            eliot_wasm_runtime::GovernorResolutionPort::resolve(&mut admission, &request)
                .expect("governor resolves");
        assert_eq!(
            governor.manifest.artifact_digest.as_str(),
            Sha256Digest::of_bytes(&artifact).as_str()
        );
        let authority =
            eliot_wasm_runtime::AuthorityResolutionPort::resolve(&mut admission, &request)
                .expect("authority resolves");
        assert_eq!(authority.work_unit.as_str(), "work-admit");
        let source = eliot_wasm_runtime::SourceVerificationPort::verify(&mut admission, &request)
            .expect("source verifies");
        let _ = source;
        let query = eliot_wasm_runtime::PromotionQuery {
            request_digest: request.request_digest().clone(),
            component_id: request.component_id.clone(),
            generation: governor.generation.clone(),
            contour: request.requested_contour,
            artifact_digest: governor.manifest.artifact_digest.clone(),
            interface_digest: governor.manifest.interface_digest.clone(),
            state_contract_digest: governor.manifest.state_contract_digest.clone(),
        };
        let promotion =
            eliot_wasm_runtime::PromotionVerificationPort::verify(&mut admission, &query)
                .expect("promotion verifies");
        assert_eq!(
            promotion.corpus_digest.as_str(),
            Sha256Digest::of_bytes(b"admit-corpus").as_str()
        );
    }

    /// Confused-deputy negative: a request naming another component is
    /// denied at the Governor gate even with valid material.
    #[test]
    fn foreign_component_request_denied() {
        let artifact = real_component();
        let input = b"admission-live-input".to_vec();
        let material = admission_material(&artifact, &input);
        let mut request = assemble_request(&material).expect("request assembles");
        request.component_id =
            eliot_wasm_runtime::CapabilityId::new("other-component").expect("component");
        let (_, admitted) =
            contour_admission(&material, &assemble_request(&material).expect("request"))
                .expect("contour admits");
        let mut admission = acquire_admission(&material, &engine_binding_for_test(), &admitted)
            .expect("factory admits");
        assert!(matches!(
            eliot_wasm_runtime::GovernorResolutionPort::resolve(&mut admission, &request),
            Err(eliot_wasm_runtime::PortError::Denied)
        ));
    }

    /// Lifecycle verdicts evaluate from retained Succeeded evidence:
    /// effect-free empty-delta success closes shadow; proposed effects
    /// deny it; progression phases stay unevaluated (never minted).
    #[test]
    fn lifecycle_verdicts_evaluate_from_evidence() {
        use eliot_wasm_runtime::{
            CancellationPolicy, EpochPolicy, InvocationDisposition, InvocationId,
            VerificationVerdict,
        };
        let material = admission_material(b"intent-artifact", b"intent-input");
        let host_digest = Sha256Digest::of_bytes(b"intent-host-image");
        let usage = || eliot_wasm_runtime::EngineUsage {
            attempted_output_bytes: 14,
            output_bytes: 14,
            host_calls: 0,
            fuel_consumed: 13,
            peak_memory_bytes: Some(65536),
            table_elements: Some(0),
            instances: 1,
            stack_bytes: None,
            enforced_stack_limit_bytes: Some(8192),
            elapsed_ms: 3,
            effective_epoch_policy: EpochPolicy {
                deadline_ticks: 100,
                cancellation: CancellationPolicy::EpochAndFuel,
            },
            epoch_ticks: Some(1),
            artifact_reads: 0,
            artifact_bytes: 0,
            accessed_artifact_digests: Vec::new(),
        };
        let succeeded = |effects: Vec<eliot_wasm_runtime::EffectProposal>,
                         delta: Option<Vec<u8>>| {
            eliot_wasm_runtime::InvocationResult {
                receipt: eliot_wasm_runtime::InvocationReceipt {
                    invocation_id: InvocationId::new("operation-verdict-001").expect("invocation"),
                    request_digest: Sha256Digest::of_bytes(b"verdict-request"),
                    disposition: InvocationDisposition::Succeeded,
                    error: None,
                    output_digest: None,
                    effect_digest: None,
                    state_delta_digest: None,
                    engine_binding: None,
                    usage: Some(usage()),
                    reconciliation_required: false,
                },
                output: Some(b"verdict-output".to_vec()),
                proposed_effects: effects,
                observed_state_delta: delta,
            }
        };
        let clean = map_invocation_result(
            &succeeded(Vec::new(), Some(Vec::new())),
            &material,
            &host_digest,
        )
        .expect("clean success responds");
        assert_eq!(clean.verdicts.shadow, VerificationVerdict::Verified);
        assert_eq!(clean.verdicts.canary, VerificationVerdict::Rejected);
        assert_eq!(clean.verdicts.rollback, VerificationVerdict::Rejected);
        assert_eq!(clean.verdicts.cutover, VerificationVerdict::Rejected);
        assert_eq!(
            clean.output_digest.as_str(),
            Sha256Digest::of_bytes(b"verdict-output").as_str()
        );
        let noisy = map_invocation_result(&succeeded(Vec::new(), None), &material, &host_digest)
            .expect("unmeasured delta still responds");
        // Unmeasured delta never manufactures verification: the response
        // carries output, but shadow stays rejected.
        assert_eq!(noisy.verdicts.shadow, VerificationVerdict::Rejected);
        assert_eq!(
            noisy.output_digest.as_str(),
            Sha256Digest::of_bytes(b"verdict-output").as_str()
        );
    }

    /// Result mapping denies without fabricating output: differential and
    /// promotion mismatches surface as admission taxonomy, every other
    /// non-success verdict fails closed with unknown outcome preserved.
    #[test]
    fn result_mapping_denies_without_output() {
        use eliot_wasm_runtime::{InvocationDisposition, InvocationId, RuntimeError};
        let material = admission_material(b"intent-artifact", b"intent-input");
        let host_digest = Sha256Digest::of_bytes(b"intent-host-image");
        let receipt = |disposition: InvocationDisposition, error: Option<RuntimeError>| {
            eliot_wasm_runtime::InvocationReceipt {
                invocation_id: InvocationId::new("operation-map-001").expect("invocation"),
                request_digest: Sha256Digest::of_bytes(b"map-request"),
                disposition,
                error,
                output_digest: None,
                effect_digest: None,
                state_delta_digest: None,
                engine_binding: None,
                usage: None,
                reconciliation_required: false,
            }
        };
        let result = |disposition: InvocationDisposition, error: Option<RuntimeError>| {
            eliot_wasm_runtime::InvocationResult {
                receipt: receipt(disposition, error),
                output: None,
                proposed_effects: Vec::new(),
                observed_state_delta: None,
            }
        };
        assert_eq!(
            map_invocation_result(
                &result(
                    InvocationDisposition::Rejected,
                    Some(RuntimeError::DifferentialMismatch)
                ),
                &material,
                &host_digest
            ),
            Err(DriveError::Admission {
                field: "differential"
            })
        );
        assert_eq!(
            map_invocation_result(
                &result(
                    InvocationDisposition::Rejected,
                    Some(RuntimeError::PromotionDenied)
                ),
                &material,
                &host_digest
            ),
            Err(DriveError::Admission { field: "promotion" })
        );
        assert_eq!(
            map_invocation_result(
                &result(InvocationDisposition::Unknown, None),
                &material,
                &host_digest
            ),
            Err(DriveError::Execution { stage: "unknown" })
        );
    }

    fn engine_binding_for_test() -> eliot_wasm_runtime::EngineBinding {
        eliot_wasm_runtime::EngineBinding {
            implementation_id: crate::child_engine::ISOLATED_CHILD_IMPLEMENTATION_ID.to_owned(),
            exact_version: crate::contour::PINNED_WASMTIME_VERSION.to_owned(),
            engine_artifact_digest: Sha256Digest::of_bytes(b"test-engine-image"),
            engine_configuration_digest: crate::wasmtime_provider::provider_configuration_digest(),
            wit_interface_digest: Sha256Digest::of_bytes(
                crate::wasmtime_provider::guest_wit_bytes(),
            ),
        }
    }
}
